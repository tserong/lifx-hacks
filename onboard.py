#!/usr/bin/env python3
#
# Author: Tim Serong <tim@wirejunkie.com>
#
# Usage: ./onboard.py [--security TYPE] [--udp] [--yes] <ssid> [password]
#
# This will send an onboarding packet to a virgin LIFX bulb, telling it to
# connect to your local WiFi network.  If the password is not given on the
# command line, it is asked for without echo (or read from stdin when piped),
# which also avoids shell quoting problems with characters like ' or !.
#
# IMPORTANT NOTES:
# - Only use this if you're connected to a virgin LIFX bulb's AP.
# - Bulbs with HomeKit support stay in HomeKit pairing mode for about 15
#   minutes after power-on and don't accept this packet during that time.
#   Leave the bulb on for 15 minutes before connecting to its AP.
# - Use --security if your network is not WPA2 AES PSK.
# - The original version was tested on LIFX Original and LIFX Color 1000.
#   An earlier version of this rewrite onboarded three LIFX Mini Day & Dusk
#   bulbs (firmware 3.90).
#   Use at own risk.
#
# Interesting commentary:
# - Both LIFX original and LIFX Color 1000 bulbs seem happy to take the
#   onboarding packet ("SetAccessPoint") via an SSL connection to TCP port
#   56700.  Older bulbs only speak TLS 1.0 with old ciphers, which modern
#   OpenSSL and Python (3.10+) refuse by default; this script re-enables that
#   for this one connection, so editing /etc/ssl/openssl.cnf is not needed.
# - The LIFX original bulbs can also be onboarded by sending the same packet
#   via UDP broadcast on port 56700 (--udp).  This is presumably wildly
#   insecure, what with not being encrypted and all.  The LIFX Color 1000
#   bulbs seem to ignore SetAccessPoint packets sent via this means.
# - Once onboarded, the bulbs don't seem to accept TCP connections to port
#   56700 anymore.
#
import argparse
import getpass
import socket
import ssl
import struct
import sys
import warnings

BULB = ("172.16.0.1", 56700)
STATION = 2  # interface: 2 = join an existing network as a client

SECURITY = {
    "open": 1,
    "wep": 2,          # allegedly not supported
    "wpa-tkip": 3,
    "wpa-aes": 4,
    "wpa2-aes": 5,
    "wpa2-tkip": 6,
    "wpa2-mixed": 7,
}

# OpenSSL SSL_OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION; Python has no named constant
OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION = 0x00040000


def onboard_packet(ssid, password, security=SECURITY["wpa2-aes"]):
    s, p = ssid.encode("utf-8"), password.encode("utf-8")
    if not 0 < len(s) <= 32:
        raise ValueError("the SSID must be 1-32 bytes")
    if len(p) > 64:
        raise ValueError("the password must be at most 64 bytes")
    payload = struct.pack("<B32s64sB", STATION, s, p, security)
    # LIFX header (36 bytes): size, protocol 1024 + addressable + tagged,
    # source, target, reserved, flags, sequence, reserved, type 305, reserved
    header = struct.pack("<HHI8s6sBBQHH", 36 + len(payload), 0x3400, 0,
                         b"", b"", 0, 0, 0, 305, 0)
    return header + payload


def tls_context():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # the bulb has a self-signed certificate
    # Older bulbs only speak TLS 1.0 with legacy ciphers and renegotiation.
    warnings.filterwarnings("ignore", message="ssl.TLSVersion.TLSv1 is deprecated",
                            category=DeprecationWarning)
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
    except ValueError:
        pass
    try:
        ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
    except ssl.SSLError:  # LibreSSL has no SECLEVEL and allows TLS 1.0 already
        pass
    ctx.options |= getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0) | OP_ALLOW_UNSAFE_LEGACY_RENEGOTIATION
    return ctx


def send_tls(packet, address=BULB):
    with socket.create_connection(address, timeout=10) as raw, \
            tls_context().wrap_socket(raw) as tls:
        print(f"Connected using {tls.version()} ({tls.cipher()[0]})")
        tls.sendall(packet)


def send_udp(packet, address=("255.255.255.255", BULB[1])):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(packet, address)


def read_password(interactive):
    if interactive:
        return getpass.getpass("Password (not shown): ")
    return sys.stdin.readline().rstrip("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Onboard a virgin LIFX bulb onto your WiFi.")
    parser.add_argument("ssid", help="name of the WiFi network the bulb should join")
    parser.add_argument("password", nargs="?",
                        help="WiFi password (omit it to be asked without echo)")
    parser.add_argument("--security", choices=SECURITY, default="wpa2-aes",
                        help="WiFi security type (default: wpa2-aes)")
    parser.add_argument("--udp", action="store_true",
                        help="send via unencrypted UDP broadcast instead of TLS (LIFX Original only)")
    parser.add_argument("--yes", "-y", action="store_true", help="don't ask for confirmation")
    args = parser.parse_args(argv)

    interactive = sys.stdin.isatty()
    password = args.password if args.password is not None else read_password(interactive)
    try:
        packet = onboard_packet(args.ssid, password, SECURITY[args.security])
    except ValueError as e:
        sys.exit(f"Error: {e}")

    if interactive and not args.yes:
        print(f"Will attempt to onboard using\n  ssid: {args.ssid}\n  security: {args.security}")
        response = input("Continue? [y/N] ")
        if not response or response[0] not in "Yy":
            sys.exit(1)

    try:
        if args.udp:
            send_udp(packet)
        else:
            send_tls(packet)
    except ssl.SSLError as e:
        sys.exit(f"TLS handshake with the bulb failed: {e}\n"
                 "- HomeKit bulbs: leave the bulb on for 15 minutes, then try again.\n"
                 "- LIFX Original: try --udp.")
    except OSError as e:
        sys.exit(f"Could not reach the bulb at {BULB[0]}:{BULB[1]}: {e}\n"
                 "- Is this computer connected to the bulb's own WiFi network?\n"
                 "- HomeKit bulbs: leave the bulb on for 15 minutes, then try again.\n"
                 "- macOS 'No route to host': allow your terminal under System Settings >"
                 " Privacy & Security > Local Network.")

    print("Onboarding packet sent. The bulb should leave its own network and join yours"
          " within a minute.")


if __name__ == "__main__":
    main()
