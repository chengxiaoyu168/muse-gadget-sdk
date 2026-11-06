/*
 * Copyright (c) Meta Platforms, Inc. and affiliates.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "net_dns.h"

#include <stdio.h>
#include <string.h>

#include "esp_log.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/timers.h"

#include "config_store.h"
#include "net_dns_policy.h"
#include "wifi_mgr.h"

static const char *TAG = "link.dns";

static esp_netif_t *s_netif;
static SemaphoreHandle_t s_mu;
static TimerHandle_t s_timer;
static bool s_inited;
static net_dns_config_t s_cfg;

static bool lock(void)
{
    return s_mu && xSemaphoreTake(s_mu, pdMS_TO_TICKS(2000)) == pdTRUE;
}

static void unlock(void)
{
    if (s_mu) xSemaphoreGive(s_mu);
}

static bool read_slot(esp_netif_dns_type_t type, uint32_t *host_order)
{
    *host_order = 0;
    if (!s_netif) return false;
    esp_netif_dns_info_t info = {0};
    if (esp_netif_get_dns_info(s_netif, type, &info) != ESP_OK) return false;
    if (info.ip.type != ESP_IPADDR_TYPE_V4 || info.ip.u_addr.ip4.addr == 0) return true;
    char text[NET_DNS_ADDR_LEN];
    snprintf(text, sizeof(text), IPSTR, IP2STR(&info.ip.u_addr.ip4));
    return net_dns_parse_ipv4(text, host_order);
}

static void read_slots(uint32_t out[3])
{
    static const esp_netif_dns_type_t types[3] = {
        ESP_NETIF_DNS_MAIN, ESP_NETIF_DNS_BACKUP, ESP_NETIF_DNS_FALLBACK,
    };
    for (int i = 0; i < 3; i++) {
        if (!read_slot(types[i], &out[i])) out[i] = 0;
    }
}

static bool write_slot(esp_netif_dns_type_t type, uint32_t host_order)
{
    char text[NET_DNS_ADDR_LEN];
    if (!net_dns_format_ipv4(host_order, text, sizeof(text))) return false;
    esp_netif_dns_info_t info = {0};
    info.ip.type = ESP_IPADDR_TYPE_V4;
    info.ip.u_addr.ip4.addr = esp_ip4addr_aton(text);
    return esp_netif_set_dns_info(s_netif, type, &info) == ESP_OK;
}

/* Caller holds s_mu. Returns true when a slot was changed. */
static bool apply_locked(void)
{
    if (!s_cfg.custom || !s_netif) return false;
    uint32_t have[3];
    read_slots(have);
    if (net_dns_slots_match(&s_cfg, have)) return false;
    uint32_t want[3];
    net_dns_expected_slots(&s_cfg, want);
    static const esp_netif_dns_type_t types[3] = {
        ESP_NETIF_DNS_MAIN, ESP_NETIF_DNS_BACKUP, ESP_NETIF_DNS_FALLBACK,
    };
    for (int i = 0; i < 3; i++) {
        if (!write_slot(types[i], want[i])) return false;
    }
    uint32_t after[3];
    read_slots(after);
    return net_dns_slots_match(&s_cfg, after);
}

static void format_slot(uint32_t host_order, char *out, size_t cap)
{
    if (!host_order || !net_dns_format_ipv4(host_order, out, cap)) {
        snprintf(out, cap, "-");
    }
}

void net_dns_maintain(void)
{
    if (!s_inited || !lock()) return;
    bool custom = s_cfg.custom;
    bool changed = apply_locked();
    char primary[NET_DNS_ADDR_LEN] = "-";
    if (changed && custom) {
        net_dns_format_ipv4(s_cfg.primary, primary, sizeof(primary));
    }
    unlock();
    if (changed && custom) {
        ESP_LOGW(TAG, "DHCP replaced the resolver; restored override primary=%s", primary);
    }
}

void net_dns_before_connect(void)
{
    net_dns_maintain();
}

void net_dns_on_got_ip(void)
{
    if (!s_inited || !lock()) return;
    uint32_t offered[3];
    read_slots(offered);
    char main_txt[NET_DNS_ADDR_LEN];
    char backup_txt[NET_DNS_ADDR_LEN];
    format_slot(offered[0], main_txt, sizeof(main_txt));
    format_slot(offered[1], backup_txt, sizeof(backup_txt));
    bool custom = s_cfg.custom;
    char primary[NET_DNS_ADDR_LEN] = "-";
    char fallback[NET_DNS_ADDR_LEN] = "-";
    if (custom) {
        net_dns_format_ipv4(s_cfg.primary, primary, sizeof(primary));
        if (s_cfg.has_fallback) net_dns_format_ipv4(s_cfg.fallback, fallback, sizeof(fallback));
    }
    apply_locked();
    unlock();
    if (custom) {
        ESP_LOGI(TAG, "dns: DHCP offered %s / %s; using override %s / %s",
                 main_txt, backup_txt, primary, fallback);
    } else {
        ESP_LOGI(TAG, "dns: DHCP %s / %s (no override)", main_txt, backup_txt);
    }
}

static void maintain_timer(TimerHandle_t timer)
{
    (void)timer;
    net_dns_maintain();
}

static void load_config(void)
{
    char primary[NET_DNS_ADDR_LEN] = {0};
    char fallback[NET_DNS_ADDR_LEN] = {0};
    bool have_primary = config_get_str(NET_DNS_KEY_PRIMARY, primary, sizeof(primary));
    bool have_fallback = config_get_str(NET_DNS_KEY_FALLBACK, fallback, sizeof(fallback));
    net_dns_config_t cfg;
    if (!net_dns_config_from_strings(have_primary ? primary : "",
                                     have_fallback ? fallback : "", &cfg)) {
        ESP_LOGW(TAG, "stored DNS override is invalid; leaving DHCP resolvers");
        memset(&s_cfg, 0, sizeof(s_cfg));
        return;
    }
    s_cfg = cfg;
}

void net_dns_init(esp_netif_t *netif)
{
    if (s_inited) return;
    s_netif = netif;
    s_mu = xSemaphoreCreateMutex();
    load_config();
    s_inited = true;
    s_timer = xTimerCreate("dns_maintain", pdMS_TO_TICKS(15000), pdTRUE, NULL, maintain_timer);
    if (s_timer) xTimerStart(s_timer, 0);
    if (s_cfg.custom) {
        char line[96];
        net_dns_format_status(&s_cfg, line, sizeof(line));
        ESP_LOGI(TAG, "saved %s", line);
        net_dns_maintain();
    } else {
        ESP_LOGI(TAG, "dns: DHCP resolvers (no override)");
    }
}

static bool persist(const net_dns_config_t *cfg)
{
    char primary[NET_DNS_ADDR_LEN];
    char fallback[NET_DNS_ADDR_LEN];
    net_dns_config_to_strings(cfg, primary, sizeof(primary), fallback, sizeof(fallback));
    if (!primary[0] || !config_set_str(NET_DNS_KEY_PRIMARY, primary)) return false;
    if (fallback[0]) {
        if (!config_set_str(NET_DNS_KEY_FALLBACK, fallback)) {
            config_erase_key(NET_DNS_KEY_PRIMARY);
            return false;
        }
    } else if (!config_erase_key(NET_DNS_KEY_FALLBACK)) {
        return false;
    }
    return true;
}

static void restore_dhcp(void)
{
    if (!s_netif || !wifi_mgr_is_connected()) return;
    esp_err_t stopped = esp_netif_dhcpc_stop(s_netif);
    esp_err_t started = esp_netif_dhcpc_start(s_netif);
    ESP_LOGI(TAG, "DHCP restart to restore resolvers: stop=%s start=%s",
             esp_err_to_name(stopped), esp_err_to_name(started));
}

bool net_dns_handle_line(const char *line, char *reply, size_t cap)
{
    net_dns_command_t cmd;
    net_dns_cmd_kind_t kind = net_dns_parse_command(line, &cmd);
    if (kind == NET_DNS_CMD_IGNORED) return false;
    if (!reply || cap == 0) return true;
    if (kind == NET_DNS_CMD_INVALID) {
        ESP_LOGW(TAG, "dns command rejected");
        snprintf(reply, cap, "@dns error invalid");
        return true;
    }
    if (!s_inited && kind != NET_DNS_CMD_STATUS) {
        snprintf(reply, cap, "@dns error not-ready");
        return true;
    }

    if (kind == NET_DNS_CMD_STATUS) {
        net_dns_config_t cfg = {0};
        if (s_inited && lock()) {
            cfg = s_cfg;
            unlock();
        }
        if (!net_dns_format_status(&cfg, reply, cap)) snprintf(reply, cap, "@dns error invalid");
        return true;
    }

    if (kind == NET_DNS_CMD_CLEAR) {
        if (!config_erase_key(NET_DNS_KEY_PRIMARY) || !config_erase_key(NET_DNS_KEY_FALLBACK)) {
            snprintf(reply, cap, "@dns error storage");
            return true;
        }
        if (lock()) {
            memset(&s_cfg, 0, sizeof(s_cfg));
            unlock();
        }
        restore_dhcp();
        net_dns_format_status(NULL, reply, cap);
        ESP_LOGI(TAG, "dns override cleared");
        return true;
    }

    if (!persist(&cmd.config)) {
        snprintf(reply, cap, "@dns error storage");
        return true;
    }
    if (lock()) {
        s_cfg = cmd.config;
        apply_locked();
        unlock();
    }
    if (!net_dns_format_status(&cmd.config, reply, cap)) {
        snprintf(reply, cap, "@dns error invalid");
        return true;
    }
    ESP_LOGI(TAG, "%s", reply);
    return true;
}
