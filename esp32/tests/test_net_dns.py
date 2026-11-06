# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import annotations

import os
import shlex
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _function_body(source: str, signature: str) -> str:
    start = source.index(signature)
    brace = source.index("{", start)
    depth = 0
    for i in range(brace, len(source)):
        if source[i] == "{":
            depth += 1
        elif source[i] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1 : i]
    raise AssertionError(f"could not find end of {signature}")


class NetDnsPolicyTest(unittest.TestCase):
    def test_policy_harness(self) -> None:
        cc = shlex.split(os.environ.get("CC", "cc"))
        if not cc or shutil.which(cc[0]) is None:
            self.skipTest("C compiler not available")
        with tempfile.TemporaryDirectory() as tmpdir:
            binary = Path(tmpdir) / "net_dns_harness"
            compiled = subprocess.run(
                [
                    *cc,
                    "-std=c11",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-I",
                    str(ROOT / "main"),
                    str(ROOT / "tests" / "net_dns_harness.c"),
                    str(ROOT / "main" / "net_dns_policy.c"),
                    "-o",
                    str(binary),
                ],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
            ran = subprocess.run(
                [str(binary)],
                cwd=ROOT,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            self.assertEqual(ran.returncode, 0, ran.stdout + ran.stderr)

    def test_override_is_not_cleared_with_pairing(self) -> None:
        source = (ROOT / "main" / "config_store.c").read_text()
        for name in ("bool config_clear_pairing(", "bool config_clear_setup(", "bool config_unpair("):
            body = _function_body(source, name)
            self.assertNotIn("dns_primary", body)
            self.assertNotIn("dns_fallback", body)
        header = (ROOT / "main" / "net_dns.h").read_text()
        self.assertIn('"dns_primary"', header)
        self.assertIn('"dns_fallback"', header)
        glue = (ROOT / "main" / "net_dns.c").read_text()
        self.assertIn("NET_DNS_KEY_PRIMARY", glue)
        self.assertIn("NET_DNS_KEY_FALLBACK", glue)
        self.assertIn("esp_netif_dhcpc_stop", glue)
        self.assertIn("esp_netif_dhcpc_start", glue)

    def test_home_link_walks_addresses_without_skipping_the_name(self) -> None:
        connect = (ROOT / "main" / "net_connect.c").read_text()
        self.assertIn("cfg.skip_common_name = false", connect)
        self.assertIn("cfg.common_name = sni", connect)
        self.assertIn("net_dns_plan_tries", connect)
        vm = (ROOT / "main" / "vm_api.c").read_text()
        self.assertIn("net_http_fill", vm)
        self.assertIn("net_dns_plan_tries", vm)
        self.assertNotIn("net_http_attempt_t attempts[", vm)
        self.assertIn("cfg.common_name = sni", vm)
        self.assertIn('esp_http_client_set_header(client, "Host", host_header)', vm)
        noise = (ROOT / "main" / "noise_control.cpp").read_text()
        session = _function_body(noise, "static session_result_t run_session(")
        self.assertIn("net_tls_connect_new", session)
        self.assertIn("cfg.skip_common_name = false", session)
        defaults = (ROOT / "sdkconfig.defaults").read_text()
        self.assertIn("CONFIG_LWIP_DNS_MAX_HOST_IP=4", defaults)
        wifi = (ROOT / "main" / "wifi_mgr.c").read_text()
        self.assertIn("net_dns_on_got_ip", wifi)
        ble = (ROOT / "components" / "muse" / "muse_ble.c").read_text()
        self.assertIn('!strcmp(cmd, "dns")', ble)
        serial = (ROOT / "main" / "sdk_token_console.c").read_text()
        self.assertIn("net_dns_handle_line", serial)


if __name__ == "__main__":
    unittest.main()
