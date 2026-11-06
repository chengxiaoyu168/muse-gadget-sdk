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

#include "net_connect.h"

#include <string.h>

#include "esp_log.h"
#include "lwip/inet.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"

#include "net_dns.h"

static const char *TAG = "link.net";

_Static_assert(NET_DNS_ADDR_LEN == 16, "IPv4 text slots are 16 bytes");

int net_resolve_ipv4(const char *host, char out[][NET_DNS_ADDR_LEN], int max)
{
    if (!host || !host[0] || !out || max <= 0) return 0;
    if (max > NET_DNS_MAX_ADDRS) max = NET_DNS_MAX_ADDRS;
    net_dns_before_connect();

    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo *res = NULL;
    int err = getaddrinfo(host, NULL, &hints, &res);
    if (err != 0 || !res) {
        ESP_LOGW(TAG, "resolve %s failed (%d)", host, err);
        if (res) freeaddrinfo(res);
        return 0;
    }

    int n = 0;
    for (struct addrinfo *ai = res; ai && n < max; ai = ai->ai_next) {
        if (!ai->ai_addr || ai->ai_family != AF_INET) continue;
        const struct sockaddr_in *in = (const struct sockaddr_in *)ai->ai_addr;
        char text[NET_DNS_ADDR_LEN];
        if (!inet_ntop(AF_INET, &in->sin_addr, text, sizeof(text))) continue;
        bool duplicate = false;
        for (int i = 0; i < n; i++) {
            if (strcmp(out[i], text) == 0) duplicate = true;
        }
        if (duplicate) continue;
        snprintf(out[n], NET_DNS_ADDR_LEN, "%s", text);
        n++;
    }
    freeaddrinfo(res);
    ESP_LOGI(TAG, "resolve %s -> %d address%s", host, n, n == 1 ? "" : "es");
    for (int i = 0; i < n; i++) ESP_LOGI(TAG, "  [%d] %s", i + 1, out[i]);
    return n;
}

static esp_tls_t *connect_one(const char *target, const char *sni, int port,
                              const esp_tls_cfg_t *base, int timeout_ms)
{
    esp_tls_t *tls = esp_tls_init();
    if (!tls) return NULL;
    esp_tls_cfg_t cfg = *base;
    cfg.timeout_ms = timeout_ms;
    cfg.common_name = sni;
    cfg.skip_common_name = false;
    cfg.addr_family = ESP_TLS_AF_INET;
    if (esp_tls_conn_new_sync(target, (int)strlen(target), port, &cfg, tls) == 1) return tls;
    esp_tls_conn_destroy(tls);
    return NULL;
}

esp_tls_t *net_tls_connect_new(const char *hostname, int port, const esp_tls_cfg_t *base)
{
    if (!hostname || !hostname[0] || !base || port <= 0 || port > 65535) return NULL;
    char addrs[NET_DNS_MAX_ADDRS][NET_DNS_ADDR_LEN];
    int n = net_resolve_ipv4(hostname, addrs, NET_DNS_MAX_ADDRS);
    int budget = base->timeout_ms > 0 ? base->timeout_ms : NET_DNS_CONNECT_BUDGET_MS;
    if (budget > NET_DNS_CONNECT_BUDGET_MS) budget = NET_DNS_CONNECT_BUDGET_MS;

    if (n <= 0) {
        ESP_LOGW(TAG, "%s: no resolved address; one direct attempt", hostname);
        return connect_one(hostname, hostname, port, base, budget);
    }

    net_dns_try_t tries[NET_DNS_MAX_TRIES];
    int n_tries = net_dns_plan_tries(n, budget, NET_DNS_ATTEMPT_CAP_MS, NET_DNS_ATTEMPT_MIN_MS,
                                     tries, NET_DNS_MAX_TRIES);
    for (int i = 0; i < n_tries; i++) {
        const char *ip = addrs[tries[i].addr_index];
        ESP_LOGI(TAG, "TLS %s address %d/%d %s timeout %dms",
                 hostname, i + 1, n_tries, ip, tries[i].timeout_ms);
        esp_tls_t *tls = connect_one(ip, hostname, port, base, tries[i].timeout_ms);
        if (tls) {
            ESP_LOGI(TAG, "TLS %s connected via %s", hostname, ip);
            return tls;
        }
        ESP_LOGW(TAG, "TLS %s via %s failed", hostname, ip);
    }
    ESP_LOGE(TAG, "TLS %s failed across %d address(es) within %dms; hostname checks stayed on. "
                  "DNS cannot help when every address is blocked.",
             hostname, n, budget);
    return NULL;
}
