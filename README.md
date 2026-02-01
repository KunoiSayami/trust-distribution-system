# Trust Distribution System (TDS)

A secure certificate and file distribution system using **age encryption** and **Ed25519 signing** over HTTP. Clients poll the server for changes and download encrypted files, with configurable post-download actions.

## Features

- **End-to-end encryption**: Files encrypted per-client using age (X25519)
- **Authenticated requests**: Ed25519 signatures for client authentication
- **Change detection**: Polling with SHA-256 hash comparison
- **Group-based access**: Clients subscribe to groups, groups contain files/directories
- **Post-download actions**: Run commands after files change (e.g., `systemctl reload nginx`)
- **Simple enrollment**: One-time tokens for easy client setup
- **Reverse proxy friendly**: Runs behind nginx without TLS

## Quick Start

### 1. Generate Server Keys

```bash
cargo run --bin server -- keygen -o /etc/tds/
```

This creates:
- `server_signing.key` - Ed25519 private key for signing
- `server_signing.pub` - Ed25519 public key (for clients)
- `server.age` - Age identity for decrypting enrollment payloads

### 2. Create Server Configuration

Create `/etc/tds/server.toml`:

```toml
version = 1

[server]
bind = "127.0.0.1:8080"

[server.keys]
signing_key_path = "/etc/tds/server_signing.key"
age_identity_path = "/etc/tds/server.age"

# Define file groups
[groups.production]
files = [
  "/etc/certs/ca.pem",
  "/etc/certs/intermediate.pem"
]
directories = [
  "/etc/letsencrypt/live/example.com"
]

[groups.web-servers]
files = [
  "/etc/nginx/nginx.conf"
]
directories = [
  "/etc/nginx/sites-enabled"
]
```

### 3. Start the Server

```bash
cargo run --bin server -- -c /etc/tds/server.toml server
```

### 4. Generate Enrollment Token

```bash
cargo run --bin server -- -c /etc/tds/server.toml token new \
  --client-id "web-01" \
  --groups "production,web-servers"
```

This outputs a token like:
```
tds-enroll-v1:abc123...:age1server...:ed25519pubkey...
```

### 5. Enroll a Client

On the client machine:

```bash
cargo run --bin client -- enroll \
  --server "https://server:8443" \
  --token "tds-enroll-v1:abc123..." \
  --config-dir /etc/tds-client/
```

### 6. Configure Client Subscriptions

Edit `/etc/tds-client/client.toml`:

```toml
version = 1

[client]
id = "web-01"
server_url = "https://server:8443"
poll_interval = 300
state_file = "/var/lib/tds/state.json"

[client.keys]
age_identity_path = "/etc/tds-client/client.age"
signing_key_path = "/etc/tds-client/client_signing.key"
server_verify_key = "base64_ed25519_pubkey"

[subscriptions.production]
output_directory = "/opt/app/certs"
preserve_structure = true

[subscriptions.production.rename]
"ca.pem" = "root-ca.pem"

[subscriptions.web-servers]
output_directory = "/etc/nginx"
preserve_structure = true

[actions.groups.production]
command = "/usr/local/bin/update-ca-trust"
args = []
on_change_only = true

[actions.groups.web-servers]
command = "/usr/bin/systemctl"
args = ["reload", "nginx"]
on_change_only = true
```

### 7. Run the Client

```bash
# Run once
cargo run --bin client -- -c /etc/tds-client/client.toml run --once

# Run continuously (polling)
cargo run --bin client -- -c /etc/tds-client/client.toml run
```

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                         SERVER                                   │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐ │
│  │ Config TOML  │  │  Ed25519     │  │   Client Registry      │ │
│  │ - clients    │  │  Signing Key │  │   (age pubkeys,        │ │
│  │ - groups     │  │              │  │    auth pubkeys,       │ │
│  │ - files      │  │              │  │    group membership)   │ │
│  └──────────────┘  └──────────────┘  └────────────────────────┘ │
│                            │                                     │
│                    ┌───────▼───────┐                            │
│                    │  HTTP API     │                            │
│                    │  /manifest    │                            │
│                    │  /files/{p}   │                            │
│                    └───────────────┘                            │
└──────────────────────────────────────────────────────────────────┘
                             │
                    HTTP (age-encrypted)
                             │
┌──────────────────────────────────────────────────────────────────┐
│                         CLIENT                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │ Config TOML  │  │  Age         │  │  Ed25519 Signing Key   │  │
│  │ - server_url │  │  Identity    │  │  (for auth)            │  │
│  │ - actions    │  │  (decrypt)   │  │                        │  │
│  │ - poll_int   │  │              │  │                        │  │
│  └──────────────┘  └──────────────┘  └────────────────────────┘  │
│                            │                                      │
│         ┌──────────────────┼──────────────────┐                  │
│         ▼                  ▼                  ▼                  │
│  ┌─────────────┐   ┌─────────────┐   ┌─────────────────────┐    │
│  │ Poll Loop   │   │  Decrypt &  │   │  Post-download      │    │
│  │ (hash check)│   │  Verify     │   │  Actions            │    │
│  └─────────────┘   └─────────────┘   └─────────────────────┘    │
└──────────────────────────────────────────────────────────────────┘
```

## HTTP API

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/v1/health` | No | Health check |
| GET | `/api/v1/manifest` | Yes | Get file list with hashes |
| GET | `/api/v1/files/{path}` | Yes | Download encrypted file |
| POST | `/api/v1/enroll` | Token | Client enrollment |

### Authentication Headers

```
Authorization: Age-Auth <ed25519_signature>
X-Client-Id: client-alpha
X-Timestamp: 1706745600000
X-Nonce: random_base64
```

## Deployment with Nginx

Server runs without TLS; nginx handles TLS termination.

### Server Config

```toml
[server]
bind = "127.0.0.1:8080"
```

### Nginx Config

```nginx
server {
    listen 443 ssl http2;
    server_name dist.example.com;

    ssl_certificate /etc/letsencrypt/live/dist.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/dist.example.com/privkey.pem;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300s;
    }
}
```

### Systemd Service

```ini
# /etc/systemd/system/tds.service
[Unit]
Description=TDS Certificate Distribution Server
After=network.target

[Service]
Type=simple
User=tds
ExecStart=/usr/local/bin/server -c /etc/tds/server.toml server
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## CLI Reference

### Server Commands

```bash
# Run the server
server -c server.toml server

# Generate server keys
server keygen -o /etc/tds/

# Token management
server -c server.toml token new --client-id "web-01" --groups "production,web-servers"
server -c server.toml token list
server -c server.toml token revoke --client-id "web-01"
```

### Client Commands

```bash
# Run client (continuous polling)
client -c client.toml run

# Run once and exit
client -c client.toml run --once

# Sync alias (same as run --once)
client -c client.toml sync

# Generate client keys manually
client keygen -o /etc/tds-client/

# Enroll with server
client enroll --server "https://server:8443" --token "tds-enroll-v1:..." --config-dir /etc/tds-client/
```

## Security

- **Encryption**: Files encrypted using age (X25519) per-client
- **Signing**: Server signs all files with Ed25519; clients verify signatures
- **Authentication**: Clients sign requests with Ed25519; includes timestamp and nonce
- **Replay protection**: Nonce cache prevents request replay within 5-minute window
- **Token security**: Enrollment tokens are one-time use, expire after 1 hour by default

## Building

```bash
# Build both binaries
cargo build --release

# Run tests
cargo test
```

## License

[![](https://www.gnu.org/graphics/agplv3-155x51.png)](https://www.gnu.org/licenses/agpl-3.0.txt)

Copyright (C) 2026 KunoiSayami

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.