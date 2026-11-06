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

#include <stdio.h>
#include <string.h>

#include "net_dns_policy.h"

static int g_failed;

#define CHECK(cond) do { \
    if (!(cond)) { \
        fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
        g_failed++; \
    } \
} while (0)

static uint32_t ip_of(const char *text)
{
    uint32_t ip = 0;
    CHECK(net_dns_parse_ipv4(text, &ip));
    return ip;
}

static void test_parse_and_usable(void)
{
    uint32_t ip = 0;
    CHECK(net_dns_parse_ipv4("1.1.1.1", &ip) && ip == 0x01010101u);
    CHECK(net_dns_parse_ipv4("8.8.8.8", &ip));
    CHECK(net_dns_parse_ipv4("192.168.1.1", &ip));
    CHECK(net_dns_parse_ipv4("10.0.0.1", &ip));
    CHECK(net_dns_parse_ipv4("169.254.1.1", &ip));
    CHECK(net_dns_parse_ipv4("100.64.0.1", &ip));
    CHECK(net_dns_parse_ipv4("255.255.255.254", &ip) && !net_dns_ipv4_usable(ip));
    CHECK(net_dns_ipv4_usable(ip_of("1.1.1.1")));
    CHECK(net_dns_ipv4_usable(ip_of("192.168.0.1")));

    const char *bad[] = {
        "", "1.2.3", "1.2.3.4.5", "01.2.3.4", "1.2.3.04", "1.2.3.",
        "1.2.3.256", "1.2.3.4 ", " 1.2.3.4", "dns.google", "1.2.3.4/32",
        "::1", "0.0.0.0", "127.0.0.1", "127.255.255.255", "224.0.0.1",
        "239.255.255.255", "240.0.0.1", "255.255.255.255", "0.1.2.3",
    };
    for (size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); i++) {
        uint32_t parsed = 1;
        bool ok = net_dns_parse_ipv4(bad[i], &parsed);
        CHECK(!ok || !net_dns_ipv4_usable(parsed));
    }
    char text[NET_DNS_ADDR_LEN];
    CHECK(net_dns_format_ipv4(ip_of("8.8.4.4"), text, sizeof(text)));
    CHECK(strcmp(text, "8.8.4.4") == 0);
}

static void test_commands(void)
{
    net_dns_command_t cmd;
    CHECK(net_dns_parse_command("wifi.ssid", &cmd) == NET_DNS_CMD_IGNORED);
    CHECK(net_dns_parse_command("dns", &cmd) == NET_DNS_CMD_STATUS);
    CHECK(net_dns_parse_command("dns=", &cmd) == NET_DNS_CMD_CLEAR);
    CHECK(net_dns_parse_command("dns=clear", &cmd) == NET_DNS_CMD_CLEAR);
    CHECK(net_dns_parse_command("dns=dhcp", &cmd) == NET_DNS_CMD_CLEAR);
    CHECK(net_dns_parse_command("dns=  dhcp  ", &cmd) == NET_DNS_CMD_CLEAR);

    CHECK(net_dns_parse_command("dns=1.1.1.1", &cmd) == NET_DNS_CMD_SET);
    CHECK(cmd.config.custom && cmd.config.primary == ip_of("1.1.1.1"));
    CHECK(!cmd.config.has_fallback);

    CHECK(net_dns_parse_command("dns=1.1.1.1,8.8.8.8", &cmd) == NET_DNS_CMD_SET);
    CHECK(cmd.config.has_fallback && cmd.config.fallback == ip_of("8.8.8.8"));
    CHECK(net_dns_parse_command("dns=1.1.1.1, 8.8.8.8", &cmd) == NET_DNS_CMD_SET);
    CHECK(cmd.config.fallback == ip_of("8.8.8.8"));
    CHECK(net_dns_parse_command("dns=8.8.8.8,8.8.8.8", &cmd) == NET_DNS_CMD_SET);
    CHECK(cmd.config.custom && !cmd.config.has_fallback);

    CHECK(net_dns_parse_command("dns=127.0.0.1", &cmd) == NET_DNS_CMD_INVALID);
    CHECK(net_dns_parse_command("dns=0.0.0.0", &cmd) == NET_DNS_CMD_INVALID);
    CHECK(net_dns_parse_command("dns=1.1.1.1,nope", &cmd) == NET_DNS_CMD_INVALID);
    CHECK(net_dns_parse_command("dns=1.1.1.1,8.8.8.8,9.9.9.9", &cmd) == NET_DNS_CMD_INVALID);
    CHECK(net_dns_parse_command("dns=224.0.0.1", &cmd) == NET_DNS_CMD_INVALID);

    char line[96];
    net_dns_config_t cfg = {0};
    CHECK(net_dns_format_status(&cfg, line, sizeof(line)));
    CHECK(strcmp(line, "@dns dhcp") == 0);
    cfg.custom = true;
    cfg.primary = ip_of("1.1.1.1");
    CHECK(net_dns_format_status(&cfg, line, sizeof(line)));
    CHECK(strcmp(line, "@dns override primary=1.1.1.1") == 0);
    cfg.has_fallback = true;
    cfg.fallback = ip_of("1.0.0.1");
    CHECK(net_dns_format_status(&cfg, line, sizeof(line)));
    CHECK(strcmp(line, "@dns override primary=1.1.1.1 fallback=1.0.0.1") == 0);
}

static void test_persistence_roundtrip(void)
{
    net_dns_command_t cmd;
    CHECK(net_dns_parse_command("dns=9.9.9.9,149.112.112.112", &cmd) == NET_DNS_CMD_SET);
    char primary[NET_DNS_ADDR_LEN];
    char fallback[NET_DNS_ADDR_LEN];
    net_dns_config_to_strings(&cmd.config, primary, sizeof(primary), fallback, sizeof(fallback));
    CHECK(strcmp(primary, "9.9.9.9") == 0);
    CHECK(strcmp(fallback, "149.112.112.112") == 0);

    net_dns_config_t loaded;
    memset(&loaded, 0x5a, sizeof(loaded));
    CHECK(net_dns_config_from_strings(primary, fallback, &loaded));
    CHECK(loaded.custom && loaded.has_fallback);
    CHECK(loaded.primary == cmd.config.primary && loaded.fallback == cmd.config.fallback);

    net_dns_config_t cleared;
    CHECK(net_dns_config_from_strings("", "", &cleared));
    CHECK(!cleared.custom && !cleared.has_fallback);
    CHECK(net_dns_config_from_strings("1.1.1.1", "", &cleared));
    CHECK(cleared.custom && !cleared.has_fallback);
    CHECK(!net_dns_config_from_strings("127.0.0.1", "", &cleared));
    CHECK(!net_dns_config_from_strings("1.1.1.1", "0.0.0.0", &cleared));
    CHECK(net_dns_config_from_strings("1.1.1.1", "1.1.1.1", &cleared));
    CHECK(cleared.custom && !cleared.has_fallback);
}

static void test_renew_and_reconnect(void)
{
    net_dns_command_t cmd;
    CHECK(net_dns_parse_command("dns=1.1.1.1,8.8.8.8", &cmd) == NET_DNS_CMD_SET);
    uint32_t slots[3];
    net_dns_expected_slots(&cmd.config, slots);
    CHECK(slots[0] == ip_of("1.1.1.1"));
    CHECK(slots[1] == ip_of("8.8.8.8") && slots[2] == ip_of("8.8.8.8"));
    CHECK(net_dns_slots_match(&cmd.config, slots));
    CHECK(!net_dns_needs_reapply(&cmd.config, slots));

    /* DHCP renew rewrites slots 0 and 1 and leaves slot 2. A successful
     * wrong answer never consults slot 2, so the override must come back. */
    uint32_t poisoned[3] = { ip_of("192.168.1.1"), ip_of("192.168.1.2"), slots[2] };
    CHECK(net_dns_needs_reapply(&cmd.config, poisoned));
    uint32_t restored[3];
    net_dns_expected_slots(&cmd.config, restored);
    CHECK(!net_dns_needs_reapply(&cmd.config, restored));

    /* Reconnect: DHCP offers resolvers, then the override is applied. */
    uint32_t offered[3] = { ip_of("10.0.0.1"), 0, 0 };
    CHECK(net_dns_needs_reapply(&cmd.config, offered));

    net_dns_config_t dhcp = {0};
    uint32_t anything[3] = { ip_of("10.1.1.1"), ip_of("10.1.1.2"), ip_of("10.1.1.3") };
    CHECK(!net_dns_needs_reapply(&dhcp, anything));
    CHECK(net_dns_slots_match(&dhcp, anything));
}

static int sum_timeouts(const net_dns_try_t *tries, int n)
{
    int sum = 0;
    for (int i = 0; i < n; i++) sum += tries[i].timeout_ms;
    return sum;
}

static void test_retry_budget(void)
{
    net_dns_try_t tries[NET_DNS_MAX_TRIES];
    int n = net_dns_plan_tries(3, 12000, 4000, 1000, tries, NET_DNS_MAX_TRIES);
    CHECK(n == 3);
    CHECK(tries[0].addr_index == 0 && tries[1].addr_index == 1 && tries[2].addr_index == 2);
    CHECK(sum_timeouts(tries, n) <= 12000);
    for (int i = 0; i < n; i++) {
        CHECK(tries[i].timeout_ms >= 1000 && tries[i].timeout_ms <= 4000);
    }

    n = net_dns_plan_tries(4, 12000, 4000, 1000, tries, NET_DNS_MAX_TRIES);
    CHECK(n == 4);
    CHECK(tries[0].addr_index == 0 && tries[3].addr_index == 3);
    CHECK(sum_timeouts(tries, n) <= 12000);
    /* Do not repeat the first address before the others have been tried. */
    for (int i = 0; i < n; i++) CHECK(tries[i].addr_index == i);

    n = net_dns_plan_tries(1, 12000, 4000, 1000, tries, NET_DNS_MAX_TRIES);
    CHECK(n == 2);
    CHECK(tries[0].addr_index == 0 && tries[1].addr_index == 0);
    CHECK(sum_timeouts(tries, n) <= 12000);
    CHECK(tries[0].timeout_ms <= 4000 && tries[1].timeout_ms <= 4000);

    n = net_dns_plan_tries(1, 1500, 4000, 1000, tries, NET_DNS_MAX_TRIES);
    CHECK(n == 1);
    CHECK(tries[0].timeout_ms <= 1500);

    CHECK(net_dns_plan_tries(0, 12000, 4000, 1000, tries, NET_DNS_MAX_TRIES) == 0);
    CHECK(net_dns_plan_tries(2, 0, 4000, 1000, tries, NET_DNS_MAX_TRIES) == 0);

    for (int addrs = 1; addrs <= 4; addrs++) {
        for (int budget = 500; budget <= 20000; budget += 250) {
            int got = net_dns_plan_tries(addrs, budget, 4000, 1000, tries, NET_DNS_MAX_TRIES);
            CHECK(got >= 0 && got <= NET_DNS_MAX_TRIES);
            if (got == 0) continue;
            CHECK(sum_timeouts(tries, got) <= budget);
            int seen[4] = {0};
            for (int i = 0; i < got; i++) {
                CHECK(tries[i].timeout_ms > 0 && tries[i].timeout_ms <= 4000);
                CHECK(tries[i].addr_index >= 0 && tries[i].addr_index < addrs);
                if (i < addrs) seen[tries[i].addr_index]++;
            }
            if (addrs > 1 && got >= addrs) {
                for (int a = 0; a < addrs; a++) CHECK(seen[a] == 1);
            }
        }
    }
}

static void test_http_plan_keeps_sni(void)
{
    char copy[3][NET_DNS_ADDR_LEN];
    snprintf(copy[0], sizeof(copy[0]), "203.0.113.10");
    snprintf(copy[1], sizeof(copy[1]), "203.0.113.11");
    snprintf(copy[2], sizeof(copy[2]), "203.0.113.12");

    net_http_attempt_t attempts[NET_DNS_MAX_TRIES];
    int n = net_http_plan("https://api.muse.ai/fetch_vms", copy, 3, NET_DNS_CONNECT_BUDGET_MS,
                          attempts, NET_DNS_MAX_TRIES);
    CHECK(n == 3);
    int total = 0;
    for (int i = 0; i < n; i++) {
        CHECK(strcmp(attempts[i].sni, "api.muse.ai") == 0);
        CHECK(strcmp(attempts[i].host_header, "api.muse.ai") == 0);
        CHECK(strstr(attempts[i].connect_url, attempts[i].addr) != NULL);
        CHECK(strstr(attempts[i].connect_url, "/fetch_vms") != NULL);
        CHECK(strstr(attempts[i].connect_url, "api.muse.ai") == NULL);
        CHECK(attempts[i].addr_index == i);
        total += attempts[i].timeout_ms;
    }
    CHECK(total <= NET_DNS_CONNECT_BUDGET_MS);
    CHECK(strcmp(attempts[0].connect_url, "https://203.0.113.10/fetch_vms") == 0);

    char host[64];
    CHECK(net_dns_url_host("https://hatch.metaaivm.com/socket", host, sizeof(host)));
    CHECK(strcmp(host, "hatch.metaaivm.com") == 0);
    n = net_http_plan("https://hatch.metaaivm.com:8443/socket", copy, 1, 12000,
                      attempts, NET_DNS_MAX_TRIES);
    CHECK(n == 2);
    CHECK(strcmp(attempts[0].sni, "hatch.metaaivm.com") == 0);
    CHECK(strcmp(attempts[0].host_header, "hatch.metaaivm.com:8443") == 0);
    CHECK(strcmp(attempts[0].connect_url, "https://203.0.113.10:8443/socket") == 0);
    CHECK(attempts[0].timeout_ms + attempts[1].timeout_ms <= 12000);

    CHECK(net_http_plan("http://api.muse.ai/fetch_vms", copy, 1, 12000, attempts, 8) == 0);
    CHECK(net_http_plan("https://api.muse.ai/fetch_vms", copy, 0, 12000, attempts, 8) == 0);
}

int main(void)
{
    test_parse_and_usable();
    test_commands();
    test_persistence_roundtrip();
    test_renew_and_reconnect();
    test_retry_budget();
    test_http_plan_keeps_sni();
    if (g_failed) {
        fprintf(stderr, "%d check(s) failed\n", g_failed);
        return 1;
    }
    return 0;
}
