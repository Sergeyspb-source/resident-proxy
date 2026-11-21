# exitnode

[Русская версия](README.md)

A proxy that exits to the internet from someone else's home computer. The owner
runs an agent, you get a key and browse through their address.

```
client → relay (VPS) → agent (PC) → site
```

The relay only connects the two sides: it never learns where you go. The agent
computer opens no ports to the internet — it dials the relay itself.

---

## Components

| Command | Runs on | Purpose |
|---|---|---|
| `relay` | a VPS with a public address | accepts agents and clients, pairs them |
| `agent` | the exit computer | keeps a link to the relay and sends traffic to the internet |
| `client` | the user's computer | exposes a local SOCKS5 and HTTP proxy |
| `hop` | an intermediate VPS | forwards a port to the final relay |
| `setup` | Windows and Linux | install, autostart, shortcuts, uninstall |

Version: **0.0.23**. Since 0.0.20 the client and the agent must be from the same
wave — they negotiate their own TLS 1.3 inside the tunnel.

---

## Quick start

### 1. Relay on a VPS

You need a domain pointing at the VPS and a certificate (Let's Encrypt is fine).

```bash
exitnode relay \
  -socks 0.0.0.0:2084 \
  -tunnel :2083 \
  -cert /etc/exitnode/tls/fullchain.pem \
  -key /etc/exitnode/tls/privkey.pem \
  -socks-tls \
  -token-file /etc/exitnode/token \
  -ui 127.0.0.1:17880
```

The token is a random string of at least 32 characters, shared by the relay and
its agents.

systemd unit:

```ini
[Unit]
Description=exitnode relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=exitnode
Group=exitnode
ExecStart=/opt/exitnode/exitnode relay -socks 0.0.0.0:2084 -tunnel :2083 \
  -cert /etc/exitnode/tls/fullchain.pem -key /etc/exitnode/tls/privkey.pem \
  -socks-tls -token-file /etc/exitnode/token -ui 127.0.0.1:17880
Restart=always
RestartSec=3
NoNewPrivileges=true
PrivateTmp=true

[Install]
WantedBy=multi-user.target
```

### 2. Agent on the exit computer

Windows:

```
proxy.exe agent -relay proxy.example.com:2083 -token-file %LOCALAPPDATA%\exitnode\token.txt ^
  -name "Home" -public-socks proxy.example.com:2084
```

Linux, one command with autostart:

```bash
./exitnode setup --systemd --invite agent.exitnode
```

or without an invite:

```bash
./exitnode setup --systemd --relay proxy.example.com:2083 \
  --token-file ./token --public-socks proxy.example.com:2084 --name "Home"
```

The unit goes to `~/.config/systemd/user`, is enabled and survives reboots.

### 3. Client on the user's computer

Windows: run `proxy.exe client`, paste the key or open the invite file. The
client lives in the tray, the window can be closed.

Linux:

```bash
./exitnode client -ui
```

A tray icon appears with a menu: open panel, start/stop, quit.

### 4. Check

```bash
curl --socks5-hostname 127.0.0.1:1080 https://ifconfig.me/ip
```

The address must be the exit computer's address.

---

## Ports

| Port | Where | Purpose |
|---|---|---|
| 2083 | relay | agents, TLS |
| 2084 | relay | clients, SOCKS5 over TLS |
| 17880 | relay | relay panel, 127.0.0.1 only |
| 17890 | agent | agent panel, 127.0.0.1 only |
| 1080 | client | local SOCKS5 |
| 8080 | client | local HTTP proxy for Windows system settings |
| 17893 | client | client window, 127.0.0.1 only |

If 1080 is taken (by Xray, for example), the client picks the next free port in
1080–1099 and shows it in the window.

---

## Keys and limits

A key is a password. It grants access to the node, so send it as an `.exitnode`
invite file rather than plain text in a chat.

The agent owner sets per key in the "Users" tab:

- **Domains** — empty means anything; otherwise only these sites and their subdomains.
- **Daily** and **monthly quota** — when exhausted, live connections are cut and
  new ones are refused. `0` means no limit.
- **Speed** — a shared cap in KB/s for upload and download across every connection
  of that key.

Changes apply immediately, no restart.

---

## Security

- The relay talks to agents and clients over TLS 1.3.
- A client sends the relay `sha256` of its key and a dummy address `e2e.invalid`.
  Only the agent knows the real destination.
- On top of that, the client and the agent run their own TLS 1.3 with mutual
  verification by the full key. The relay sees volume and timing, not sites or
  content.
- To the relay the key hash is a routing identifier, not a pass: without the full
  key the connection to the agent cannot be established.
- Panels listen on `127.0.0.1` only. Remote access goes through an SSH tunnel.
- The relay is exposed to the internet, so it runs limits and bans (below).

---

## Gateway protection

Ready-made files live in `deploy/`:

```bash
apt-get install -y fail2ban
install -m 644 deploy/fail2ban-exitnode.conf  /etc/fail2ban/filter.d/exitnode.conf
install -m 644 deploy/fail2ban-exitnode.local /etc/fail2ban/jail.d/exitnode.local
install -m 644 deploy/exitnode-guard.nft      /etc/exitnode/guard.nft
install -m 644 deploy/exitnode-guard.service  /etc/systemd/system/exitnode-guard.service
systemctl daemon-reload
systemctl enable --now exitnode-guard fail2ban
```

- **fail2ban** reads the relay journal and bans an IP for 30 minutes after 12
  failures in 10 minutes. The ban closes only 2083 and 2084.
- **exitnode-guard** limits new connections: 900 per minute and 400 concurrent per
  IP on 2084, 30 per minute on 2083.

---

## Panels

**Agent panel** (`127.0.0.1:17890`) — three tabs: overview with a chart, users
with keys and limits, settings with autostart.

**Relay panel** (`127.0.0.1:17880`) — connected nodes, active sessions, current
speed and traffic per node.

From a home computer reach the relay panel through a tunnel:

```bash
ssh -L 17880:127.0.0.1:17880 root@VPS
```

then open `http://127.0.0.1:17880/`.

---

## Second hop

To hide the client's address from the final relay as well, put an intermediate
VPS in between:

```bash
exitnode hop -listen 0.0.0.0:2084 -target 203.0.113.10:2084 -max-conns 512
```

The client points at the intermediate VPS but keeps the final certificate name:

```bash
exitnode client -server VPS1:2084 -server-name proxy.example.com -tls -key-file key.txt
```

The client's TLS terminates at the final relay; the intermediate VPS sees only
ciphertext.

---

## Updates

The panel checks the latest release through `/api/update`. The manifest
`update.json` (version and sha256 of the files) is signed with ed25519, the
public key is embedded in the binary (`internal/update/pubkey.go`). Without a
valid signature the version is shown in red as "signature not verified".

Publishing a release:

```bash
go run ./cmd/sign -key release-key.json -version 0.0.24 -dir bin ^
  -files exitnode-agent.exe,exitnode-client.exe,exitnode-linux
gh release create v0.0.24 bin/exitnode-agent.exe bin/exitnode-client.exe ^
  bin/exitnode-linux bin/update.json
```

The private key is kept outside the repository. Lose it and new releases can no
longer be signed.

---

## Install and remove

`exitnode setup` flags:

| Flag | Purpose |
|---|---|
| `--agent` / `--client` | install on Windows |
| `--invite FILE` | take address and key from an invite |
| `--systemd` | Linux: service with autostart |
| `--desktop` | Linux: menu shortcut and `.exitnode` association |
| `--relay`, `--token-file`, `--public-socks`, `--name` | node parameters without an invite |
| `--uninstall` | remove the program and the service |

Uninstall on Linux: `./exitnode setup --uninstall`. Keys and state stay in
`~/.cache/exitnode`.

---

## Files and paths

| What | Windows | Linux |
|---|---|---|
| Agent token | `%LOCALAPPDATA%\exitnode\token.txt` | `~/.config/exitnode/agent.json` |
| Client settings | `%LOCALAPPDATA%\exitnode\client.json` | `~/.cache/exitnode/client.json` |
| Agent keys | `%LOCALAPPDATA%\exitnode` | `~/.cache/exitnode` |
| Proxy backup | `%LOCALAPPDATA%\exitnode\sysproxy.json` | — |

---

## Troubleshooting

**The agent does not connect.** Check that `proxy.example.com:2083` is reachable
from that computer and the token matches the relay.

**The client says "unknown key".** The key was removed or belongs to an agent that
is offline.

**Pages fail while a speed test works.** Usually the key's domain allowlist or an
exhausted quota — check the agent panel.

**Port 1080 is busy.** The client takes 1081–1099 and shows the port in the window.

**Windows system proxy is not picked up.** Chrome and Edge follow it, Firefox
needs "system proxy settings" enabled manually.

---

## Development

```bash
go build ./...
go vet ./...
go test ./...
```

Release build:

```bash
go build -ldflags "-H=windowsgui -s -w" -o bin/proxy.exe ./cmd/proxy
GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o bin/exitnode-linux ./cmd/proxy
```

The version lives in `internal/buildinfo/version.go`.
