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

#include "net_dns_policy.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

static const char *skip_ws(const char *s, const char *end)
{
    while (s < end && isspace((unsigned char)*s)) s++;
    return s;
}

static const char *rtrim(const char *begin, const char *end)
{
    while (end > begin && isspace((unsigned char)end[-1])) end--;
    return end;
}

static bool span_eq(const char *begin, const char *end, const char *lit)
{
    size_t n = (size_t)(end - begin);
    return strlen(lit) == n && memcmp(begin, lit, n) == 0;
}

bool net_dns_parse_ipv4(const char *text, uint32_t *host_order)
{
    if (!text || !host_order) return false;
    const char *p = text;
    uint32_t ip = 0;
    for (int oct = 0; oct < 4; oct++) {
        if (*p < '0' || *p > '9') return false;
        if (*p == '0' && p[1] >= '0' && p[1] <= '9') return false;
        int value = 0;
        int digits = 0;
        while (*p >= '0' && *p <= '9') {
            value = value * 10 + (*p - '0');
            if (value > 255 || ++digits > 3) return false;
            p++;
        }
        if (digits == 0) return false;
        ip = (ip << 8) | (uint32_t)value;
        if (oct < 3) {
            if (*p != '.') return false;
            p++;
        }
    }
    if (*p != '\0') return false;
    *host_order = ip;
    return true;
}

bool net_dns_ipv4_usable(uint32_t host_order)
{
    uint32_t lead = (host_order >> 24) & 0xffu;
    return lead != 0 && lead != 127 && lead < 224;
}

bool net_dns_format_ipv4(uint32_t host_order, char *out, size_t cap)
{
    if (!out || cap == 0) return false;
    int n = snprintf(out, cap, "%u.%u.%u.%u",
                     (unsigned)((host_order >> 24) & 255u),
                     (unsigned)((host_order >> 16) & 255u),
                     (unsigned)((host_order >> 8) & 255u),
                     (unsigned)(host_order & 255u));
    return n > 0 && (size_t)n < cap;
}

static bool parse_server(const char *begin, const char *end, uint32_t *ip)
{
    char buf[NET_DNS_ADDR_LEN];
    size_t n = (size_t)(end - begin);
    if (n == 0 || n >= sizeof(buf)) return false;
    memcpy(buf, begin, n);
    buf[n] = '\0';
    uint32_t parsed = 0;
    if (!net_dns_parse_ipv4(buf, &parsed) || !net_dns_ipv4_usable(parsed)) return false;
    *ip = parsed;
    return true;
}

net_dns_cmd_kind_t net_dns_parse_command(const char *line, net_dns_command_t *out)
{
    if (out) memset(out, 0, sizeof(*out));
    if (!line || !out) return NET_DNS_CMD_IGNORED;
    if (strcmp(line, "dns") == 0) {
        out->kind = NET_DNS_CMD_STATUS;
        return NET_DNS_CMD_STATUS;
    }
    if (strncmp(line, "dns=", 4) != 0) return NET_DNS_CMD_IGNORED;

    const char *begin = line + 4;
    const char *end = begin + strlen(begin);
    begin = skip_ws(begin, end);
    end = rtrim(begin, end);
    if (begin == end || span_eq(begin, end, "clear") || span_eq(begin, end, "dhcp")) {
        out->kind = NET_DNS_CMD_CLEAR;
        return NET_DNS_CMD_CLEAR;
    }

    const char *comma = NULL;
    for (const char *p = begin; p < end; p++) {
        if (*p == ',') {
            if (comma) {
                out->kind = NET_DNS_CMD_INVALID;
                return NET_DNS_CMD_INVALID;
            }
            comma = p;
        }
    }

    uint32_t primary = 0;
    uint32_t fallback = 0;
    bool has_fallback = false;
    if (!comma) {
        if (!parse_server(begin, end, &primary)) {
            out->kind = NET_DNS_CMD_INVALID;
            return NET_DNS_CMD_INVALID;
        }
    } else {
        const char *fb = skip_ws(comma + 1, end);
        const char *primary_end = rtrim(begin, comma);
        if (!parse_server(begin, primary_end, &primary) || !parse_server(fb, end, &fallback)) {
            out->kind = NET_DNS_CMD_INVALID;
            return NET_DNS_CMD_INVALID;
        }
        has_fallback = fallback != primary;
    }

    out->kind = NET_DNS_CMD_SET;
    out->config.custom = true;
    out->config.primary = primary;
    out->config.has_fallback = has_fallback;
    out->config.fallback = has_fallback ? fallback : 0;
    return NET_DNS_CMD_SET;
}

bool net_dns_config_from_strings(const char *primary, const char *fallback, net_dns_config_t *out)
{
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!primary || !primary[0]) return true;
    uint32_t primary_ip = 0;
    if (!net_dns_parse_ipv4(primary, &primary_ip) || !net_dns_ipv4_usable(primary_ip)) return false;
    out->custom = true;
    out->primary = primary_ip;
    if (fallback && fallback[0]) {
        uint32_t fallback_ip = 0;
        if (!net_dns_parse_ipv4(fallback, &fallback_ip) || !net_dns_ipv4_usable(fallback_ip)) {
            return false;
        }
        if (fallback_ip != primary_ip) {
            out->has_fallback = true;
            out->fallback = fallback_ip;
        }
    }
    return true;
}

void net_dns_config_to_strings(const net_dns_config_t *cfg,
                               char *primary, size_t primary_cap,
                               char *fallback, size_t fallback_cap)
{
    if (primary && primary_cap) primary[0] = '\0';
    if (fallback && fallback_cap) fallback[0] = '\0';
    if (!cfg || !cfg->custom) return;
    if (primary) net_dns_format_ipv4(cfg->primary, primary, primary_cap);
    if (fallback && cfg->has_fallback) net_dns_format_ipv4(cfg->fallback, fallback, fallback_cap);
}

bool net_dns_format_status(const net_dns_config_t *cfg, char *out, size_t cap)
{
    if (!out || cap == 0) return false;
    if (!cfg || !cfg->custom) {
        return snprintf(out, cap, "@dns dhcp") > 0;
    }
    char primary[NET_DNS_ADDR_LEN];
    char fallback[NET_DNS_ADDR_LEN];
    if (!net_dns_format_ipv4(cfg->primary, primary, sizeof(primary))) return false;
    int n;
    if (cfg->has_fallback) {
        if (!net_dns_format_ipv4(cfg->fallback, fallback, sizeof(fallback))) return false;
        n = snprintf(out, cap, "@dns override primary=%s fallback=%s", primary, fallback);
    } else {
        n = snprintf(out, cap, "@dns override primary=%s", primary);
    }
    return n > 0 && (size_t)n < cap;
}

void net_dns_expected_slots(const net_dns_config_t *cfg, uint32_t out_host_order[3])
{
    if (!out_host_order) return;
    if (!cfg || !cfg->custom) {
        out_host_order[0] = out_host_order[1] = out_host_order[2] = 0;
        return;
    }
    uint32_t second = cfg->has_fallback ? cfg->fallback : cfg->primary;
    out_host_order[0] = cfg->primary;
    out_host_order[1] = second;
    out_host_order[2] = second;
}

bool net_dns_slots_match(const net_dns_config_t *cfg, const uint32_t slots_host_order[3])
{
    if (!cfg || !cfg->custom) return true;
    if (!slots_host_order) return false;
    uint32_t want[3];
    net_dns_expected_slots(cfg, want);
    return slots_host_order[0] == want[0]
        && slots_host_order[1] == want[1]
        && slots_host_order[2] == want[2];
}

bool net_dns_needs_reapply(const net_dns_config_t *cfg, const uint32_t slots_host_order[3])
{
    return cfg && cfg->custom && !net_dns_slots_match(cfg, slots_host_order);
}

int net_dns_plan_tries(int n_addrs, int budget_ms, int cap_ms, int min_ms,
                       net_dns_try_t *out, int max_out)
{
    if (!out || max_out <= 0 || n_addrs <= 0 || budget_ms <= 0 || cap_ms <= 0 || min_ms <= 0) {
        return 0;
    }
    if (n_addrs > NET_DNS_MAX_ADDRS) n_addrs = NET_DNS_MAX_ADDRS;
    if (min_ms > cap_ms) min_ms = cap_ms;
    int passes = n_addrs == 1 ? 2 : 1;
    int tries = n_addrs * passes;
    if (tries > max_out) tries = max_out;
    if (tries > NET_DNS_MAX_TRIES) tries = NET_DNS_MAX_TRIES;
    while (tries > 1 && budget_ms / tries < min_ms) tries--;
    int each = budget_ms / tries;
    if (each > cap_ms) each = cap_ms;
    if (each < min_ms) each = budget_ms < min_ms ? budget_ms : min_ms;
    if (each > budget_ms / tries) each = budget_ms / tries;
    if (each <= 0) return 0;
    for (int i = 0; i < tries; i++) {
        out[i].addr_index = i % n_addrs;
        out[i].timeout_ms = each;
    }
    int extra = budget_ms - each * tries;
    if (extra > 0 && out[tries - 1].timeout_ms < cap_ms) {
        int room = cap_ms - out[tries - 1].timeout_ms;
        if (extra > room) extra = room;
        out[tries - 1].timeout_ms += extra;
    }
    return tries;
}

static bool split_https(const char *url, char *host, size_t host_cap, int *port,
                        char *path, size_t path_cap)
{
    static const char prefix[] = "https://";
    if (!url || strncmp(url, prefix, sizeof(prefix) - 1) != 0) return false;
    const char *p = url + sizeof(prefix) - 1;
    if (*p == '\0' || *p == '/' || *p == ':' || *p == '@' || *p == '[') return false;
    const char *host_begin = p;
    while (*p && *p != '/' && *p != ':' && *p != '?' && *p != '#') {
        if (*p == '@' || *p == ' ' || *p == '\\') return false;
        p++;
    }
    size_t host_len = (size_t)(p - host_begin);
    if (host_len == 0 || host_len >= host_cap || host_len > 253) return false;
    int parsed_port = 443;
    if (*p == ':') {
        p++;
        if (*p < '0' || *p > '9') return false;
        int value = 0;
        while (*p >= '0' && *p <= '9') {
            value = value * 10 + (*p - '0');
            if (value > 65535) return false;
            p++;
        }
        if (value <= 0) return false;
        parsed_port = value;
    }
    if (*p != '\0' && *p != '/' && *p != '?') return false;
    memcpy(host, host_begin, host_len);
    host[host_len] = '\0';
    *port = parsed_port;
    if (!path) return true;
    int n;
    if (*p == '\0') n = snprintf(path, path_cap, "/");
    else if (*p == '?') n = snprintf(path, path_cap, "/%s", p);
    else n = snprintf(path, path_cap, "%s", p);
    return n > 0 && (size_t)n < path_cap;
}

bool net_dns_url_host(const char *url, char *host, size_t cap)
{
    int port = 0;
    return split_https(url, host, cap, &port, NULL, 0);
}

int net_http_plan(const char *url, const char addrs[][NET_DNS_ADDR_LEN], int n_addrs,
                  int budget_ms, net_http_attempt_t *out, int max_out)
{
    if (!url || !addrs || !out || n_addrs <= 0) return 0;
    char host[256];
    char path[256];
    int port = 0;
    if (!split_https(url, host, sizeof(host), &port, path, sizeof(path))) return 0;
    net_dns_try_t tries[NET_DNS_MAX_TRIES];
    int n_tries = net_dns_plan_tries(n_addrs, budget_ms, NET_DNS_ATTEMPT_CAP_MS,
                                     NET_DNS_ATTEMPT_MIN_MS, tries, NET_DNS_MAX_TRIES);
    if (n_tries <= 0 || n_tries > max_out) return 0;
    for (int i = 0; i < n_tries; i++) {
        int index = tries[i].addr_index;
        if (index < 0 || index >= n_addrs || !addrs[index][0]) return 0;
        memset(&out[i], 0, sizeof(out[i]));
        out[i].addr_index = index;
        out[i].timeout_ms = tries[i].timeout_ms;
        snprintf(out[i].addr, sizeof(out[i].addr), "%s", addrs[index]);
        snprintf(out[i].sni, sizeof(out[i].sni), "%s", host);
        int hn = port == 443
            ? snprintf(out[i].host_header, sizeof(out[i].host_header), "%s", host)
            : snprintf(out[i].host_header, sizeof(out[i].host_header), "%s:%d", host, port);
        int un = port == 443
            ? snprintf(out[i].connect_url, sizeof(out[i].connect_url), "https://%s%s", addrs[index], path)
            : snprintf(out[i].connect_url, sizeof(out[i].connect_url), "https://%s:%d%s",
                       addrs[index], port, path);
        if (hn <= 0 || (size_t)hn >= sizeof(out[i].host_header) ||
            un <= 0 || (size_t)un >= sizeof(out[i].connect_url) ||
            strcmp(out[i].sni, host) != 0) {
            return 0;
        }
    }
    return n_tries;
}
