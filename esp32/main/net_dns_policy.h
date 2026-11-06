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

#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Pure DNS-override and connect-budget policy. No ESP-IDF calls, so the host
 * tests can run it. The device side (net_dns.c, net_connect.c) applies it.
 *
 * ESP-IDF v6.0.3 esp_tls_hostname_to_fd() keeps only address_info, never
 * ai_next, and a blackholed TCP connect logs "[sock=N] select() timeout"
 * (ESP_ERR_ESP_TLS_CONNECTION_TIMEOUT). esp_http_client maps that to
 * ESP_ERR_HTTP_CONNECT with no HTTP status. lwIP can return several A
 * records only when DNS_MAX_HOST_IP is raised above its default of 1.
 * DHCP's ACK, including a renew/rebind that does not change the address,
 * rewrites DNS slots 0 and 1 (dhcp_handle_ack). Slot 2 is left alone, but
 * lwIP never asks it when slot 0 already answered — a wrong answer is not
 * a timeout. An override therefore has to replace slot 0 and be put back
 * after every renew.
 */

#define NET_DNS_ADDR_LEN 16
#define NET_DNS_MAX_ADDRS 4
#define NET_DNS_MAX_TRIES 8
#define NET_DNS_CONNECT_BUDGET_MS 12000
#define NET_DNS_ATTEMPT_CAP_MS 4000
#define NET_DNS_ATTEMPT_MIN_MS 1000

typedef struct {
    bool custom;
    uint32_t primary; /* host byte order; valid only when custom */
    bool has_fallback;
    uint32_t fallback;
} net_dns_config_t;

typedef enum {
    NET_DNS_CMD_IGNORED = 0,
    NET_DNS_CMD_STATUS,
    NET_DNS_CMD_SET,
    NET_DNS_CMD_CLEAR,
    NET_DNS_CMD_INVALID,
} net_dns_cmd_kind_t;

typedef struct {
    net_dns_cmd_kind_t kind;
    net_dns_config_t config;
} net_dns_command_t;

typedef struct {
    int addr_index;
    int timeout_ms;
} net_dns_try_t;

typedef struct {
    char connect_url[384];
    char sni[256];
    char host_header[272];
    char addr[NET_DNS_ADDR_LEN];
    int addr_index;
    int timeout_ms;
} net_http_attempt_t;

bool net_dns_parse_ipv4(const char *text, uint32_t *host_order);
bool net_dns_ipv4_usable(uint32_t host_order);
bool net_dns_format_ipv4(uint32_t host_order, char *out, size_t cap);

/* "dns", "dns=", "dns=clear", "dns=dhcp", "dns=<ip>", "dns=<ip>,<ip>". */
net_dns_cmd_kind_t net_dns_parse_command(const char *line, net_dns_command_t *out);

/* Empty primary is a valid DHCP config. A bad string returns false. */
bool net_dns_config_from_strings(const char *primary, const char *fallback,
                                 net_dns_config_t *out);
void net_dns_config_to_strings(const net_dns_config_t *cfg,
                               char *primary, size_t primary_cap,
                               char *fallback, size_t fallback_cap);

/* "@dns dhcp" or "@dns override primary=... [fallback=...]". */
bool net_dns_format_status(const net_dns_config_t *cfg, char *out, size_t cap);

/* Slot 0 is queried first. A custom config fills every slot so a timeout
 * cannot fall through to a resolver the router just wrote. Not custom:
 * match is always true (DHCP servers are left untouched). */
void net_dns_expected_slots(const net_dns_config_t *cfg, uint32_t out_host_order[3]);
bool net_dns_slots_match(const net_dns_config_t *cfg, const uint32_t slots_host_order[3]);
bool net_dns_needs_reapply(const net_dns_config_t *cfg, const uint32_t slots_host_order[3]);

/* One pass over each address. A single address may be tried twice. The sum
 * of timeout_ms is at most budget_ms, and each try is at most cap_ms. */
int net_dns_plan_tries(int n_addrs, int budget_ms, int cap_ms, int min_ms,
                       net_dns_try_t *out, int max_out);

/* HTTPS only. connect_url uses the address; sni and host_header keep the
 * name so certificate checks and the Host header are unchanged. 0 means
 * the caller should open the original URL. */
int net_http_plan(const char *url, const char addrs[][NET_DNS_ADDR_LEN], int n_addrs,
                  int budget_ms, net_http_attempt_t *out, int max_out);

bool net_dns_url_host(const char *url, char *host, size_t cap);

#ifdef __cplusplus
}
#endif
