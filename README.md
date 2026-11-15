# MozVPS

A self-hosted management panel and terminal controller for the Firefox IP Protection core from `free-mozilla-vpn`. Proxy listeners use SOCKS5. The upstream `mozvpn.py` core is kept byte-identical; Mozilla sign-in, anti-bot behavior, and upstream authentication logic are not modified.

> **Release note:** publish all files in this package to the `main` branch of `arefhere51/mozvps` before using the one-line installer or updater. This project is independent of Mozilla.

## VPS installation

A Debian/Ubuntu VPS with systemd and administrative access is required. After publishing the files to the target repository, run:

```bash
curl -fsSL https://raw.githubusercontent.com/arefhere51/mozvps/main/install.sh | sudo bash
```

The installer places the application in `/opt/mozvps` and persistent data in `/var/lib/mozvps`. The service is enabled at boot. Starting the service starts the panel and starts the proxy worker when at least one authenticated account is available.

Run the English terminal menu:

```bash
mozvps
```

Direct commands:

```bash
mozvps start
mozvps stop
mozvps restart
mozvps status
mozvps add-account
mozvps list-accounts
mozvps update
mozvps logs
mozvps info
mozvps uninstall
```

The terminal menu includes `Add Firefox/Mozilla account` and `Uninstall MozVPS and delete all data`. Uninstall requires the exact confirmation `DELETE MOZVPS` and permanently removes the application, accounts, passwords, sessions, tokens, TOTP secrets, settings, logs, service unit, and `/var/lib/mozvps`.

## Web panel

The web panel is intentionally Persian and initially listens on port `1234`:

```text
http://SERVER-IP-or-domain:1234
Initial password: admin
```

Change the initial password immediately. The panel can configure its port, manage service state, add or remove Mozilla accounts, configure location ports, show quota information, and display service events.

The Persian panel also provides a Mozilla HTTP proxy switch. Enter the proxy host and port, enable it, and save. New account authentication and the worker's Mozilla control-plane requests then use `http://HOST:PORT`. Disable the switch and save to return to direct access; an active worker is restarted so the change takes effect. This proxy is for Mozilla control-plane traffic and is separate from the public SOCKS5 listeners.

### TLS on the same port

Public HTTP does not encrypt panel or Mozilla credentials. Account creation through public HTTP is intentionally blocked. The application can terminate TLS directly on port `1234`, so port `443` is not required. Copy `deploy/mozvps-tls.conf.example` to a systemd drop-in after making the certificate readable by the `mozvps` service user:

```bash
sudo install -d -o mozvps -g mozvps -m 700 /var/lib/mozvps/tls
sudo install -o mozvps -g mozvps -m 600 /path/to/fullchain.pem /var/lib/mozvps/tls/fullchain.pem
sudo install -o mozvps -g mozvps -m 600 /path/to/privkey.pem /var/lib/mozvps/tls/privkey.pem
sudo install -d /etc/systemd/system/mozvps.service.d
sudo cp /opt/mozvps/deploy/mozvps-tls.conf.example /etc/systemd/system/mozvps.service.d/tls.conf
sudo systemctl daemon-reload
sudo systemctl restart mozvps
```

Then open:

```text
https://DOMAIN:1234/
```

The certificate and key can also be configured with `MOZVPS_PANEL_TLS_CERT` and `MOZVPS_PANEL_TLS_KEY`. Both files must be readable by `mozvps`. The project does not issue certificates or open firewall ports automatically.

For local-only access, use a systemd override:

```bash
sudo systemctl edit mozvps
```

```ini
[Service]
Environment=MOZVPS_PANEL_HOST=127.0.0.1
```

Then restart the service. You can access the local panel through an SSH tunnel:

```bash
ssh -N -L 1234:127.0.0.1:1234 USER@SERVER_IP
```

Open `http://127.0.0.1:1234/` on your computer. The browser connection is local while the SSH tunnel is encrypted.

Panel passwords are hashed. Mozilla account passwords, TOTP secrets, sessions, and upstream account records are stored locally to support reconnection and automatic rotation; the application data directory is permission-restricted but is not encrypted at rest.

## Mozilla accounts and locations

Add a Mozilla account from the English terminal menu with `mozvps add-account` or from the Persian web panel. The terminal helper does not echo the password or TOTP value. Email verification, anti-bot challenges, network restrictions, and Mozilla service permissions remain controlled by Mozilla and the unchanged upstream core; successful sign-in is not guaranteed.

Multiple authenticated accounts are supported. When Mozilla reports that the current account has no remaining quota, the core can rotate to another account with a stored session and available quota. Rotation follows the quota reported by Mozilla; this project does not impose a fixed 50 GB value. Active connections can be interrupted and expired sessions may require authentication again.

After the server list is available, each location can be assigned a unique port and enabled or disabled. Changes are applied when the worker rebuilds or restarts. The list and availability depend on Mozilla server responses.

## SOCKS5

The built-in SOCKS5 proxy has no client authentication. Listeners therefore bind to `127.0.0.1` by default. To use a listener from another computer, use SSH port forwarding:

```bash
ssh -N -L 23000:127.0.0.1:23000 USER@SERVER_IP
```

Then configure the client to use SOCKS5 at `127.0.0.1:23000`. Replace `23000` with the selected location port. SOCKS5 supports TCP CONNECT; it is not UDP ASSOCIATE and is not a full-device VPN.

If direct network access is intentionally required, set `MOZVPS_PROXY_BIND=0.0.0.0` in a systemd override. Anyone reaching an unauthenticated listener can consume your quota; restrict it with a firewall or a trusted private network.

## Updates and backups

`mozvps update` fetches only from `https://github.com/arefhere51/mozvps` and preserves `/var/lib/mozvps`. Back up the persistent data securely before updating. The installer validates the repository files, stages updates, keeps the previous deployment for rollback, and does not replace persistent data.

## Local tests

Run the offline test suite without a real Mozilla account:

```bash
python3 -m unittest discover -s tests -v
```

These tests cover panel authentication, CSRF handling, port validation, SOCKS5 byte forwarding, listener binding, account rotation selection, and mocked authentication. They are not a substitute for testing with a real Mozilla account, live quota, real SOCKS5 traffic, or a production VPS.

## Source and licensing

The core is derived from [dev3haven/free-mozilla-vpn](https://github.com/dev3haven/free-mozilla-vpn). The inspected upstream repository did not contain a clear license file. Check the required permission and the licenses of all dependencies before public redistribution or publishing a derivative work. The upstream core may use TLS connections without certificate verification in some situations; that behavior remains unchanged to preserve the requested core.
