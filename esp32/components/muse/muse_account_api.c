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

#include "muse_account_api.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net_dns_policy.h"

#include "cJSON.h"
#include "esp_crt_bundle.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "muse_account_api";
_Static_assert(MUSE_ACCOUNT_ADDR_LEN == NET_DNS_ADDR_LEN, "resolver text width");
static int (*s_resolve_ipv4)(const char *host, char out[][MUSE_ACCOUNT_ADDR_LEN], int max);

void muse_account_set_ipv4_resolver(int (*resolve)(const char *host,
                                                    char out[][MUSE_ACCOUNT_ADDR_LEN],
                                                    int max))
{
    s_resolve_ipv4 = resolve;
}

#define FETCH_URL "https://api.muse.ai/fetch_vms"
#define MAX_RESPONSE (32 * 1024)
#define ATTEMPTS 3   /* the first DNS lookup after Wi-Fi comes up often fails */

typedef struct {
    char *buf;
    size_t len;
} resp_t;

static esp_err_t on_http(esp_http_client_event_t *evt)
{
    resp_t *r = evt->user_data;
    if (evt->event_id != HTTP_EVENT_ON_DATA || r->len + evt->data_len > MAX_RESPONSE) {
        return ESP_OK;
    }
    memcpy(r->buf + r->len, evt->data, evt->data_len);
    r->len += evt->data_len;
    return ESP_OK;
}

/* Returns the HTTP status, or 0 if the request never completed.
 * sni/host_header NULL keeps the URL's own name (certificate check unchanged). */
static int fetch_at(const char *url, const char *auth, resp_t *r,
                    const char *sni, const char *host_header, int timeout_ms)
{
    esp_http_client_config_t cfg = {
        .url = url,
        .timeout_ms = timeout_ms > 0 ? timeout_ms : 15000,
        .buffer_size = 4096,
        .buffer_size_tx = 4096,
        .event_handler = on_http,
        .user_data = r,
        .crt_bundle_attach = esp_crt_bundle_attach,
        .disable_auto_redirect = true,
    };
    if (sni && sni[0]) cfg.common_name = sni;
    esp_http_client_handle_t c = esp_http_client_init(&cfg);
    if (!c) {
        return 0;
    }
    esp_http_client_set_header(c, "Authorization", auth);
    if (host_header && host_header[0]) esp_http_client_set_header(c, "Host", host_header);
    esp_http_client_set_header(c, "X-API-Version", "1.0.0");
    esp_err_t err = esp_http_client_perform(c);
    int status = esp_http_client_get_status_code(c);
    esp_http_client_cleanup(c);
    /* perform() reports 401 as an error; the status still tells us what happened. */
    if (status == 401 || status == 403) {
        return status;
    }
    return err == ESP_OK ? status : 0;
}

static int fetch(const char *auth, resp_t *r)
{
    return fetch_at(FETCH_URL, auth, r, NULL, NULL, 0);
}

static void copy_str(char *out, size_t cap, const cJSON *item)
{
    out[0] = '\0';
    if (cJSON_IsString(item) && item->valuestring) {
        strlcpy(out, item->valuestring, cap);
    }
}

/* The id is also the first label of the VM's wss://<id>.<domain>/ URL. */
static void id_from_url(const char *url, char *out, size_t cap)
{
    const char *p = url ? strstr(url, "://") : NULL;
    const char *dot = p ? strchr(p + 3, '.') : NULL;
    out[0] = '\0';
    if (dot && (size_t)(dot - p - 3) < cap) {
        memcpy(out, p + 3, dot - p - 3);
        out[dot - p - 3] = '\0';
    }
}

int muse_hatch_api_find_vm(const char *device_token, const char *want_vm, muse_hatch_vm_t *out)
{
    memset(out, 0, sizeof(*out));
    size_t auth_len = strlen(device_token) + 8;
    char *auth = malloc(auth_len);
    resp_t r = { .buf = heap_caps_malloc(MAX_RESPONSE, MALLOC_CAP_SPIRAM) };
    if (!auth || !r.buf) {
        free(auth);
        free(r.buf);
        return MUSE_HATCH_API_FAILED;
    }
    snprintf(auth, auth_len, "Bearer %s", device_token);

    int status = 0;
    char host[256];
    char addrs[NET_DNS_MAX_ADDRS][NET_DNS_ADDR_LEN];
    int n_addrs = 0;
    if (s_resolve_ipv4 && net_dns_url_host(FETCH_URL, host, sizeof(host))) {
        n_addrs = s_resolve_ipv4(host, addrs, NET_DNS_MAX_ADDRS);
    }
    /* One attempt record. The array used to be ~8 KB and overflowed the
     * task that calls this. */
    net_dns_try_t tries[NET_DNS_MAX_TRIES];
    int n_tries = n_addrs > 0
        ? net_dns_plan_tries(n_addrs, NET_DNS_CONNECT_BUDGET_MS, NET_DNS_ATTEMPT_CAP_MS,
                             NET_DNS_ATTEMPT_MIN_MS, tries, NET_DNS_MAX_TRIES)
        : 0;
    if (n_tries > 0) {
        for (int i = 0; i < n_tries; i++) {
            net_http_attempt_t attempt;
            int index = tries[i].addr_index;
            if (index < 0 || index >= n_addrs ||
                !net_http_fill(FETCH_URL, addrs[index], index, tries[i].timeout_ms, &attempt)) {
                break;
            }
            r.len = 0;
            status = fetch_at(attempt.connect_url, auth, &r, attempt.sni,
                              attempt.host_header, attempt.timeout_ms);
            if (status == 401 || status == 403 || (status >= 200 && status < 500)) break;
            ESP_LOGW(TAG, "fetch_vms address %d/%d %s failed (HTTP %d)",
                     i + 1, n_tries, attempt.addr, status);
        }
    }
    for (int i = 0; n_tries == 0 && i < ATTEMPTS; i++) {
        r.len = 0;
        status = fetch(auth, &r);
        if (status == 401 || status == 403 || (status >= 200 && status < 500)) {
            break;
        }
        ESP_LOGW(TAG, "fetch_vms attempt %d failed (HTTP %d)", i + 1, status);
        vTaskDelay(pdMS_TO_TICKS(500 << i));
    }
    free(auth);
    if (status == 401 || status == 403) {
        ESP_LOGW(TAG, "fetch_vms: token rejected (HTTP %d)", status);
        free(r.buf);
        return MUSE_HATCH_API_AUTH;
    }
    if (status != 200) {
        ESP_LOGW(TAG, "fetch_vms failed (HTTP %d)", status);
        free(r.buf);
        return MUSE_HATCH_API_FAILED;
    }

    int rc = MUSE_HATCH_API_FAILED;
    cJSON *root = cJSON_ParseWithLength(r.buf, r.len);
    free(r.buf);
    cJSON *list = cJSON_GetObjectItem(root, "vm_list");
    const cJSON *pick = NULL, *entry;
    int count = 0;
    cJSON_ArrayForEach(entry, list) {
        const cJSON *url = cJSON_GetObjectItem(entry, "vm_ws_url");
        if (!cJSON_IsString(url)) {
            url = cJSON_GetObjectItem(entry, "vm_url");
        }
        if (!cJSON_IsString(cJSON_GetObjectItem(entry, "vm_auth_token"))) {
            continue;
        }
        char id[128];
        copy_str(id, sizeof(id), cJSON_GetObjectItem(entry, "vm_id"));
        if (!id[0]) {
            id_from_url(cJSON_IsString(url) ? url->valuestring : NULL, id, sizeof(id));
        }
        count++;
        ESP_LOGI(TAG, "VM %s (%s)%s", id, cJSON_GetStringValue(cJSON_GetObjectItem(entry, "vm_name")) ?: "",
                 cJSON_IsTrue(cJSON_GetObjectItem(entry, "default")) ? " default" : "");
        bool match = want_vm[0] ? strcmp(id, want_vm) == 0
                                : (!pick || cJSON_IsTrue(cJSON_GetObjectItem(entry, "default")));
        if (match && id[0]) {
            pick = entry;
            strlcpy(out->vm_id, id, sizeof(out->vm_id));
        }
    }
    if (pick) {
        copy_str(out->vm_name, sizeof(out->vm_name), cJSON_GetObjectItem(pick, "vm_name"));
        out->vm_token = strdup(cJSON_GetObjectItem(pick, "vm_auth_token")->valuestring);
        rc = out->vm_token ? 0 : MUSE_HATCH_API_FAILED;
    } else {
        ESP_LOGW(TAG, "fetch_vms: %d VMs, none %s%s", count, want_vm[0] ? "with id " : "usable", want_vm);
    }
    cJSON_Delete(root);
    return rc;
}
