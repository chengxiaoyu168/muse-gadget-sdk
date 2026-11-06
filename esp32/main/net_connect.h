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

#include "esp_tls.h"
#include "net_dns_policy.h"

#ifdef __cplusplus
extern "C" {
#endif

/* IPv4 A records in resolver order, duplicates removed, at most
 * NET_DNS_MAX_ADDRS. 0 when DNS has no answer. Reapplies a DNS override
 * first so a lease renew cannot answer this lookup from the router. */
int net_resolve_ipv4(const char *host, char out[][NET_DNS_ADDR_LEN], int max);

/* Connected esp_tls, or NULL. Walks every resolved address inside the
 * caller's timeout (capped at NET_DNS_CONNECT_BUDGET_MS). common_name is
 * the hostname and skip_common_name is forced off, so SNI and the
 * certificate check stay on the name while TCP uses one address. */
esp_tls_t *net_tls_connect_new(const char *hostname, int port, const esp_tls_cfg_t *cfg);

#ifdef __cplusplus
}
#endif
