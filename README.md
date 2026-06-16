# Trust Distribution System (TDS)

A secure certificate and file distribution system using **AES-256-GCM encryption** and **Ed25519 signing** over HTTP. Clients poll the server for changes and download encrypted files with resumable chunked transfers and configurable post-download actions.

## Features

- **End-to-end encryption**: Files encrypted per-client using X25519 ECDH key exchange + AES-256-GCM
- **Resumable downloads**: Files split into 1 MB chunks; interrupted downloads resume from the last verified chunk
- **Authenticated requests**: Ed25519 signatures for client authentication
- **Change detection**: Polling with SHA-256 hash comparison
- **Group-based access**: Clients subscribe to groups, groups contain paths (files or directories, auto-detected)
- **Post-download actions**: Run commands after files change (e.g., `systemctl reload nginx`); identical commands triggered by multiple files are deduplicated per cycle
- **Simple enrollment**: One-time tokens for easy client setup
- **Reverse proxy friendly**: Runs behind nginx without TLS

## Quick Start

### 1. Generate Server Keys

```bash
cargo run --bin server -- keygen -o /etc/tds/
```

This creates:
- `server_signing.key` — Ed25519 private key for signing
- `server_signing.pub` — Ed25519 public key (share with clients via config)
- `server.x25519` — X25519 identity for decrypting enrollment payloads

### 2. Create Server Configuration

Create `/etc/tds/server.toml`:

```toml
version = 1

[server]
bind = "127.0.0.1:8080"

# Optional: TLS config (if not using reverse proxy)
# [server.tls]
# cert_path = "/etc/tds/cert.pem"
# key_path = "/etc/tds/key.pem"

[server.keys]
signing_key_path = "/etc/tds/server_signing.key"
x25519_identity_path = "/etc/tds/server.x25519"

# Admin credentials for token management (generate with hash-password and totp-setup)
[server.admin]
password_hash = "$argon2id$..."   # from: server hash-password <password>
totp_secret = "BASE32SECRET"      # from: server totp-setup --account admin

# Enrollment settings
[server.enrollment]
enabled = true           # Enable enrollment endpoint (default: true)
token_expiry_hours = 1   # Default token lifetime in hours
allow_localhost = false  # Allow token-free enrollment from localhost (dev only)

# Define file groups
[groups.production]
paths = [
  "/etc/certs/ca.pem",
  "/etc/certs/intermediate.pem",
  "/etc/letsencrypt/live/example.com"
]

[groups.web-servers]
paths = [
  "/etc/nginx/nginx.conf",
  "/etc/nginx/sites-enabled"
]
```

### 3. Start the Server

```bash
cargo run --bin server -- -c /etc/tds/server.toml server
```

### 4. Generate Enrollment Token

With the server running, generate a token using admin credentials:

```bash
# Using config file (auto-reads TOTP secret if configured)
cargo run --bin server -- token -c /etc/tds/server.toml -p <admin-password> new \
  --client-id "web-01" \
  --groups "production,web-servers"

# Or specify server URL and TOTP manually
cargo run --bin server -- token -s http://127.0.0.1:8080 -p <admin-password> -t <totp-code> new \
  --client-id "web-01" \
  --groups "production,web-servers"
```

This outputs a token like:
```
tds-enroll-v2:abc123...:X25519-PUBLIC-KEY-1:aabbcc...:ed25519pubkey...
```

### 5. Enroll a Client

On the client machine:

```bash
cargo run --bin client -- enroll \
  --server "https://server:8443" \
  --token "tds-enroll-v2:abc123..." \
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
x25519_identity_path = "/etc/tds-client/client.x25519"
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

# Alternatively, define a named template and reference it from multiple groups:
# [actions.templates.reload-nginx]
# command = "/usr/bin/systemctl"
# args = ["reload", "nginx"]
# on_change_only = true
#
# [actions.groups]
# web-servers = "reload-nginx"
# web-configs = "reload-nginx"   # same command → runs only once per cycle
#
# Run multiple actions in sequence using a list (mix of templates and inline):
# [actions.groups]
# web-servers = ["reload-nginx", {command = "/usr/bin/notify-send", args = ["deployed"]}]
#
# Use immediate = true to bypass per-cycle deduplication (runs once per triggering file/group):
# [actions.templates.audit-log]
# command = "/usr/bin/logger"
# args = ["-t", "tds", "file changed"]
# on_change_only = true
# immediate = true
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
│  │ - clients    │  │  Signing Key │  │   (x25519 pubkeys,     │ │
│  │ - groups     │  │              │  │    auth pubkeys,       │ │
│  │ - files      │  │              │  │    group membership)   │ │
│  └──────────────┘  └──────────────┘  └────────────────────────┘ │
│                            │                                     │
│                    ┌───────▼────────┐                           │
│                    │  HTTP API      │                           │
│                    │  /manifest     │                           │
│                    │  /files/{p}    │                           │
│                    │  /chunks/{p}   │                           │
│                    │  /chunk/{i}/{p}│                           │
│                    └────────────────┘                           │
└──────────────────────────────────────────────────────────────────┘
                             │
               HTTP (AES-256-GCM encrypted, chunked)
                             │
┌──────────────────────────────────────────────────────────────────┐
│                         CLIENT                                    │
│  ┌──────────────┐  ┌──────────────┐  ┌────────────────────────┐  │
│  │ Config TOML  │  │  X25519      │  │  Ed25519 Signing Key   │  │
│  │ - server_url │  │  Identity    │  │  (for auth)            │  │
│  │ - actions    │  │  (decrypt)   │  │                        │  │
│  │ - poll_int   │  │              │  │                        │  │
│  └──────────────┘  └──────────────┘  └────────────────────────┘  │
│                            │                                      │
│         ┌──────────────────┼──────────────────┐                  │
│         ▼                  ▼                  ▼                  │
│  ┌─────────────┐   ┌──────────────┐   ┌─────────────────────┐   │
│  │ Poll Loop   │   │  Resumable   │   │  Post-download      │   │
│  │ (hash check)│   │  Chunk DL +  │   │  Actions            │   │
│  │             │   │  Verify/Dec  │   │                     │   │
│  └─────────────┘   └──────────────┘   └─────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
```

## HTTP API

### Client Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| GET | `/api/v1/health` | No | Health check |
| GET | `/api/v1/manifest` | Client | Get file list with hashes |
| GET | `/api/v1/files/{path}` | Client | Download encrypted file (all chunks) |
| GET | `/api/v1/chunks/{path}` | Client | Get chunk manifest for resumable download |
| GET | `/api/v1/chunk/{index}/{path}` | Client | Download a single encrypted chunk |
| POST | `/api/v1/enroll` | Token | Client enrollment |

### Admin Endpoints

| Method | Path | Auth | Purpose |
|--------|------|------|---------|
| POST | `/api/v1/admin/tokens` | Admin | Create enrollment tokens |
| GET | `/api/v1/admin/tokens` | Admin | List pending tokens |
| DELETE | `/api/v1/admin/tokens/{client_id}` | Admin | Revoke tokens for client |
| POST | `/api/v1/admin/groups/{group}/force-sync` | Admin | Activate force re-download for a group |
| DELETE | `/api/v1/admin/groups/{group}/force-sync` | Admin | Clear force-sync for a group |

### Client Authentication Headers

```
Authorization: Age-Auth <ed25519_signature>
X-Client-Id: client-alpha
X-Timestamp: 1706745600000
X-Nonce: random_base64
```

### Admin Authentication Headers

```
Authorization: Admin <password>
X-TOTP-Code: 123456
```

## Encryption

Files are encrypted using a hybrid scheme:

1. **Key exchange**: An ephemeral X25519 keypair is generated per file. ECDH with the client's stored X25519 public key produces a shared secret.
2. **Key derivation**: The shared secret is fed into HKDF-SHA256 with a random 12-byte file nonce to produce a 256-bit AES key.
3. **Chunked encryption**: The plaintext is split into 1 MB chunks. Each chunk is encrypted independently with AES-256-GCM using a per-chunk nonce (derived from the file nonce XOR'd with the chunk index) and the chunk index as authenticated additional data (AAD), which prevents chunk reordering.
4. **Signing**: The server signs the chunk manifest and each full file response with Ed25519.

This design means each chunk can be independently verified and decrypted, enabling resumable downloads.

### Key File Formats

| File | Format | Example |
|------|--------|---------|
| `server.x25519` / `client.x25519` | Text, `X25519-SECRET-KEY-1:<hex>` | `X25519-SECRET-KEY-1:9e7c...` |
| `server_signing.key` | JSON, base64 | `{"private_key":"...","public_key":"..."}` |
| `server_signing.pub` | JSON, base64 | `{"public_key":"..."}` |

The `x25519_public_key` stored in server config per client uses the format `X25519-PUBLIC-KEY-1:<hex>`.

## Resumable Downloads

When downloading a file the client:

1. Requests the chunk manifest (`GET /chunks/{path}`) which returns the number of chunks, the ephemeral public key, and a server signature.
2. Downloads each chunk individually (`GET /chunk/{i}/{path}`), decrypts it in-place (AES-GCM authentication confirms chunk integrity), and writes it to a `.tds-tmp` file at the correct byte offset.
3. Saves progress to the state file after each verified chunk. On restart, verified chunks are skipped.
4. If the server re-encrypts the file (different ephemeral public key), progress is discarded and the download restarts.
5. On completion, the temp file is atomically renamed to the final path and progress state is cleared.

## Force Sync

Admins can force all clients subscribed to a group to re-download every file in
that group on their next sync cycle, regardless of whether the content has changed.
This is useful for testing the end-to-end distribution pipeline.

```bash
# Trigger a force re-download for a group
server group -p <password> -c server.toml force-sync --group production

# Clear the flag (clients return to normal hash-based change detection)
server group -p <password> -c server.toml clear-force-sync --group production
```

The force-sync token is embedded in the signed manifest, so it cannot be injected
by a third party. It is transient — cleared automatically when the server restarts.
Clients record the token in their state file once all files in the group are
successfully downloaded, preventing repeated re-downloads on subsequent polls.

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

# Token management (via HTTP to running server, requires admin credentials)
server token -p <password> [-s <server>] [-c <config>] [-t <totp>] new \
  --client-id "web-01" --groups "production,web-servers" [--count <n>] [--expiry <hours>]
server token -p <password> [-s <server>] [-c <config>] [-t <totp>] list
server token -p <password> [-s <server>] [-c <config>] [-t <totp>] revoke --client-id "web-01"

# Group management (via HTTP to running server, requires admin credentials)
server group -p <password> [-s <server>] [-c <config>] [-t <totp>] force-sync --group <name>
server group -p <password> [-s <server>] [-c <config>] [-t <totp>] clear-force-sync --group <name>

# Utility commands for admin setup
server hash-password <password>              # Generate Argon2id hash for config
server totp-setup --account <name>           # Generate new TOTP secret
server totp <secret>                         # Generate current TOTP code
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
client enroll --server "https://server:8443" --token "tds-enroll-v2:..." --config-dir /etc/tds-client/
```

## Migration from v0.2 (Age Encryption)

Version 0.3 replaces Age encryption with AES-256-GCM. Existing deployments must:

1. Regenerate all keys: `server keygen` and `client keygen` (or re-enroll)
2. Update server config: rename `age_identity_path` → `x25519_identity_path` and `age_public_key` → `x25519_public_key` in all `[clients.*]` sections
3. Update client config: rename `age_identity_path` → `x25519_identity_path`
4. Replace `server.age` and `client.age` key files with the new `.x25519` files
5. Re-enroll clients to exchange new public keys (`tds-enroll-v2` tokens are required; old `tds-enroll-v1` tokens are rejected)

## Security

- **Encryption**: X25519 ECDH key exchange + HKDF-SHA256 key derivation + AES-256-GCM per chunk
- **Integrity**: AES-GCM authentication tag per chunk; chunk index bound into AAD to prevent reordering
- **Signing**: Server signs manifests and file responses with Ed25519; clients verify before use
- **Client authentication**: Clients sign requests with Ed25519; includes timestamp and nonce
- **Admin authentication**: Password (Argon2id hash) + TOTP two-factor for token management
- **Replay protection**: Nonce cache prevents request replay within 5-minute window
- **Token security**: Enrollment tokens are one-time use, expire after 1 hour by default
- **Localhost bypass**: Optional development mode to skip token validation for local connections

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
