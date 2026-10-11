# LIFX Hacks

Use at own risk.  The story of onboard.py can be found at
http://ourobengr.com/2016/05/oops-that-didnt-work/

## onboard.py

Puts a LIFX bulb that is in setup mode on your WiFi without the LIFX app.

1. Power on the bulb. It broadcasts its own WiFi network ("LIFX ...").
   Bulbs with HomeKit support stay in HomeKit pairing mode for about 15
   minutes; leave them on for 15 minutes first.
2. Connect your computer to the bulb's network.
3. Run:

   ```
   ./onboard.py "Your WiFi name"
   ```

   You are asked for the password without echo. Piping it in also works
   (`printf '%s\n' "$PASS" | ./onboard.py "Your WiFi name"`). The old form
   `./onboard.py <ssid> <password>` still works, but puts the password in
   your shell history and needs careful quoting for `'` or `!`.
4. Reconnect your computer to your own WiFi. The bulb joins it within a minute.

Options:

- `--security wpa2-aes|wpa2-mixed|wpa2-tkip|wpa-aes|wpa-tkip|open` (default `wpa2-aes`).
  The bulb needs WPA2 (or mixed WPA2/WPA3); WPA3-only networks don't work.
- `--udp`: send the packet by unencrypted UDP broadcast instead of TLS
  (LIFX Original only).
- `--yes`: skip the confirmation question.

No extra packages are needed: Python 3 standard library only.
Tested against a simulated TLS 1.0-only bulb on Python 3.12 (OpenSSL 3.0) and
3.14 (OpenSSL 3.5).

### Troubleshooting

- **TLS handshake errors** (`SSLV3_ALERT_HANDSHAKE_FAILURE`, `UNSAFE_LEGACY_RENEGOTIATION_DISABLED`):
  older bulbs only speak TLS 1.0. The script allows TLS 1.0, legacy ciphers and
  legacy renegotiation for this one connection, so editing `/etc/ssl/openssl.cnf`
  is no longer needed (Python 3.10+ sets its own TLS minimum, so that setting
  often had no effect).
  The script prints the negotiated TLS version, which helps when reporting issues.
- **Connection timed out although the bulb answers ping**: a HomeKit bulb is
  probably still in HomeKit pairing mode. Leave it on for 15 minutes, then try again.
  If the bulb never accepts the connection, try `--udp` (that works on the LIFX Original).
- **macOS: "No route to host"**: allow your terminal app under
  System Settings > Privacy & Security > Local Network.
- **Finding the bulb afterwards**: it gets an address from your router via DHCP.
  If it is on a separate VLAN or subnet, LIFX broadcast discovery won't reach it
  from your main network; look it up in your router (the MAC starts with `d0:73:d5`).
