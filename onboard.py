#!/usr/bin/env python3
#
# Author: Tim Serong <tim@wirejunkie.com>
#
# Usage: ./onboard.py <ssid> <password>
#
# This will send an onboarding packet to a virgin LIFX bulb, telling it to
# connect to your local WiFi network using the SSID and password provided
# as command line arguments.  There is no error checking, so if it breaks
# you get to keep both pieces.
#
# IMPORTANT NOTES:
# - Only use this if you're connected to a virgin LIFX bulb's AP.
# - If your wireless network is using security other than WPA2 AES PSK, change
#   the final value appended to onboard_packet appropriately.
# - This script has been tested three or four times on one LIFX Original
#   and one LIFX Color 1000 bulb.  It worked fine for me, but use at own risk.
# - If you get an SSL error, try temporarily setting MinProtocol = TLSv1.0
#   in /etc/ssl/openssl.cnf (https://github.com/tserong/lifx-hacks/issues/2)
#
# Interesting commentary:
# - Both LIFX original and LIFX Color 1000 bulbs seem happy to take the
#   onboarding packet ("SetAccessPoint") via an SSL connection to TCP port
#   56700.
# - The LIFX original bulbs can also be onboarded by sending the same packet
#   via UDP broadcast on port 56700.  This is presumably wildly insecure,
#   what with not being encrypted and all.  The LIFX Color 1000 bulbs seem to
#   ignore SetAccessPoint packets sent via this means.
# - Once onboarded, the bulbs don't seem to accept TCP connections to port
#   56700 anymore.
#
import sys, socket, ssl

if len(sys.argv) != 3:
    print("Usage: {0} <ssid> <password>".format(sys.argv[0]))
    exit(1)

ssid = sys.argv[1][0:32]
passwd = sys.argv[2][0:64]

print("Will attempt to onboard using\n"
      "  ssid: {0}\n"
      "  password: {1}".format(ssid, passwd))
response = input("Continue? [y/N] ")
if not response or response[0] not in ['Y', 'y']:
    exit(1)

onboard_packet = b'\x86\x00\x00\x34\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x31\x01\x00\x00\x02'
onboard_packet += ssid.ljust(32, '\x00').encode('utf-8')
onboard_packet += passwd.ljust(64, '\x00').encode('utf-8')
# 0x01 == OPEN
# 0x02 == WEP_PSK (allegedly not supported)
# 0x03 == WPA_TKIP_PSK
# 0x04 == WPA_AES_PSK
# 0x05 == WPA2_AES_PSK
# 0x06 == WPA2_TKIP_PSK
# 0x07 == WPA2_MIXED_PSK
onboard_packet += b'\x05'

ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
ctx.minimum_version = ssl.TLSVersion.TLSv1
#ctx.set_ciphers('@SECLEVEL=0:ALL')
ctx.set_ciphers('@SECLEVEL=0:TLS13-AES-256-GCM-SHA384:TLS13-CHACHA20-POLY1305-SHA256:TLS13-AES-128-GCM-SHA256:ECDH+AESGCM:ECDH+CHACHA20:DH+AESGCM:DH+CHACHA20:ECDH+AES256:DH+AES256:ECDH+AES128:DH+AES:ECDH+HIGH:DH+HIGH:RSA+AESGCM:RSA+AES:RSA+HIGH:!aNULL:!eNULL:!MD5:!3DES')
#ctx.set_ciphers('@SECLEVEL=0:AES256-SHA')
ctx.options |= 0x4 # OP_LEGACY_SERVER_CONNECT
sock = ctx.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
sock.connect(('172.16.0.1', 56700))
sock.write(onboard_packet)

print("LIFX bulb probably onboarded.  Best of luck ;-)")

