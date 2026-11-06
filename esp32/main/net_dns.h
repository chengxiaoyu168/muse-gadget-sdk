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

#include "esp_netif.h"

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Opt-in primary/fallback DNS, stored in the existing homehub NVS namespace
 * (dns_primary, dns_fallback). Absent keys leave DHCP resolvers untouched.
 * Pairing reset and setup reset keep the keys: they are device network
 * settings, not account credentials. Clear ("dns=", "dns=clear", "dns=dhcp")
 * erases them and restarts the DHCP client so the router supplies resolvers
 * again.
 *
 * Serial, on a Muse board or a Link-only board: >dns, >dns=1.1.1.1,
 * >dns=1.1.1.1,1.0.0.1, >dns=clear. The encrypted BLE setup command is the
 * same text without the '>'.
 */

#define NET_DNS_KEY_PRIMARY "dns_primary"
#define NET_DNS_KEY_FALLBACK "dns_fallback"

void net_dns_init(esp_netif_t *netif);

/* Put the saved override back if DHCP has replaced it. Safe before init. */
void net_dns_maintain(void);
void net_dns_on_got_ip(void);
void net_dns_before_connect(void);

/* line is "dns" or "dns=...". False when the line is some other command.
 * reply is "@dns ..." and never contains credentials. */
bool net_dns_handle_line(const char *line, char *reply, size_t cap);

#ifdef __cplusplus
}
#endif
