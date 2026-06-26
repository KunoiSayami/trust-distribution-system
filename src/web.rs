use std::net::SocketAddr;
use std::time::{Duration, Instant};

use axum::{
    Json, Router,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use encryption::ChunkedEncrypted;
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::admin;
use crate::configure::{ClientEntry, ServerConfig};
use crate::types::{
    AppState, CachedEncryption, EnrollPayload, EnrollRequest, EnrollResponse, ErrorResponse,
    HealthResponse, ManifestBinaryEntry, ManifestDirectives, ManifestFileEntry, ManifestResponse,
};

const CHUNK_CACHE_TTL: Duration = Duration::from_secs(600); // 10 minutes

/// Create the router with all API endpoints
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/health", get(health_handler))
        .route("/api/v1/manifest", get(manifest_handler))
        .route("/api/v1/files/{*path}", get(file_handler))
        .route("/api/v1/chunks/{*path}", get(chunk_manifest_handler))
        .route("/api/v1/chunk/{index}/{*path}", get(chunk_handler))
        .route("/api/v1/enroll", post(enroll_handler))
        // Admin endpoints
        .route("/api/v1/admin/tokens", post(admin::admin_create_tokens))
        .route("/api/v1/admin/tokens", get(admin::admin_list_tokens))
        .route(
            "/api/v1/admin/tokens/{client_id}",
            delete(admin::admin_revoke_tokens),
        )
        .route(
            "/api/v1/admin/groups/{group}/force-sync",
            post(admin::admin_set_force_sync),
        )
        .route(
            "/api/v1/admin/groups/{group}/force-sync",
            delete(admin::admin_clear_force_sync),
        )
        .route("/api/v1/admin/cache", delete(admin::admin_clear_cache))
        .route(
            "/api/v1/admin/cache/{client_id}",
            delete(admin::admin_clear_client_cache),
        )
        .with_state(state)
}

/// Health check endpoint - no auth required
async fn health_handler() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "healthy".to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        timestamp: chrono::Utc::now().timestamp_millis(),
    })
}

/// Manifest endpoint - returns list of files with hashes
async fn manifest_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<ManifestResponse>, (StatusCode, Json<ErrorResponse>)> {
    let client_id = authenticate_request(&state, &headers).await?;

    let config = state.config.read().await;
    let files = config.get_client_files(&client_id);

    let mut entries = Vec::new();
    for file_info in files {
        let metadata = match tokio::fs::metadata(&file_info.source_path).await {
            Ok(m) => m,
            Err(e) => {
                log::warn!(
                    "Failed to read metadata for {}: {e}",
                    file_info.source_path.display()
                );
                continue;
            }
        };

        let modified_at = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        if let Ok(content) = tokio::fs::read(&file_info.source_path).await {
            let hash = format!("sha256:{}", hex::encode(Sha256::digest(&content)));
            entries.push(ManifestFileEntry {
                path: file_info.relative_path,
                content_hash: hash,
                size: content.len() as u64,
                group: file_info.group,
                modified_at,
            });
        }
    }

    // Collect active directives for groups present in this client's manifest only,
    // to avoid leaking force-sync tokens for groups the client doesn't belong to.
    let relevant_groups: std::collections::HashSet<&str> =
        entries.iter().map(|e| e.group.as_str()).collect();
    let mut directives_map = std::collections::BTreeMap::new();
    for group in &relevant_groups {
        if let Some(d) = state.group_directives().get(*group) {
            directives_map.insert((*group).to_string(), d.clone());
        }
    }
    let directives = ManifestDirectives(directives_map);

    // Build binary entries for this client
    let binary_infos = config.get_client_binaries(&client_id);
    let mut binary_entries: Vec<ManifestBinaryEntry> = Vec::new();
    for binary_info in binary_infos {
        let metadata = match tokio::fs::metadata(&binary_info.source_path).await {
            Ok(m) => m,
            Err(e) => {
                log::warn!(
                    "Failed to read metadata for binary {}: {e}",
                    binary_info.source_path.display()
                );
                continue;
            }
        };

        let modified_at = metadata
            .modified()
            .ok()
            .and_then(|t| t.duration_since(std::time::UNIX_EPOCH).ok())
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);

        if let Ok(content) = tokio::fs::read(&binary_info.source_path).await {
            let hash = format!("sha256:{}", hex::encode(Sha256::digest(&content)));
            binary_entries.push(ManifestBinaryEntry {
                path: format!("__binary__/{}", binary_info.name),
                name: binary_info.name,
                content_hash: hash,
                size: content.len() as u64,
                modified_at,
            });
        }
    }

    // Sign files_json || directives_json || binaries_json
    let files_data = serde_json::to_vec(&entries).unwrap_or_default();
    let directives_data = serde_json::to_vec(&directives).unwrap_or_default();
    let binaries_data = serde_json::to_vec(&binary_entries).unwrap_or_default();
    let mut manifest_data =
        Vec::with_capacity(files_data.len() + directives_data.len() + binaries_data.len());
    manifest_data.extend_from_slice(&files_data);
    manifest_data.extend_from_slice(&directives_data);
    manifest_data.extend_from_slice(&binaries_data);

    let (signature, timestamp) = encryption::sign(&state.server_signing_key, &manifest_data)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(e.to_string(), "SIGN_ERROR")),
            )
        })?;

    log::trace!(
        "[manifest sign] timestamp={} files_len={} directives_len={} binaries_len={} sig={}",
        timestamp,
        files_data.len(),
        directives_data.len(),
        binaries_data.len(),
        BASE64.encode(&signature),
    );

    Ok(Json(ManifestResponse {
        version: 3,
        timestamp,
        files: entries,
        directives,
        binaries: binary_entries,
        signature: BASE64.encode(&signature),
    }))
}

/// Resolve a virtual download path to a source file path on disk.
/// Regular file paths are looked up via `get_client_files`; paths starting with
/// `__binary__/` are resolved via `get_client_binaries`.
fn resolve_source_path(
    config: &ServerConfig,
    client_id: &str,
    path: &str,
) -> Option<std::path::PathBuf> {
    if let Some(name) = path.strip_prefix("__binary__/") {
        config
            .get_client_binaries(client_id)
            .into_iter()
            .find(|b| b.name == name)
            .map(|b| b.source_path)
    } else {
        config
            .get_client_files(client_id)
            .into_iter()
            .find(|f| f.relative_path == path)
            .map(|f| f.source_path)
    }
}

/// Get or populate the chunk cache for a (client_id, path) pair.
/// Returns an error response if the file can't be read or encrypted.
async fn get_or_populate_cache(
    state: &AppState,
    client_id: &str,
    path: &str,
) -> Result<(ChunkedEncrypted, String), (StatusCode, Json<ErrorResponse>)> {
    // Read file and compute hash first — the hash is part of the cache key so that
    // a changed file always produces a fresh encryption rather than serving stale chunks.
    let config = state.config.read().await;
    let client = config.clients.get(client_id).ok_or_else(|| {
        (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse::new("Client not found", "CLIENT_NOT_FOUND")),
        )
    })?;

    let recipient =
        encryption::X25519Recipient::from_str(&client.x25519_public_key).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(e.to_string(), "INVALID_RECIPIENT")),
            )
        })?;

    let source_path = resolve_source_path(&config, client_id, path).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new("File not found", "FILE_NOT_FOUND")),
        )
    })?;

    drop(config);

    let content = tokio::fs::read(&source_path).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(e.to_string(), "READ_ERROR")),
        )
    })?;

    let content_hash = format!("sha256:{}", hex::encode(Sha256::digest(&content)));

    // Cache key includes content_hash so stale entries for old file versions are never used.
    let cache_key = (
        client_id.to_string(),
        path.to_string(),
        content_hash.clone(),
    );

    if let Some(entry) = state.chunk_cache.get(&cache_key) {
        if entry.expires_at > Instant::now() {
            return Ok((entry.payload.clone(), entry.content_hash.clone()));
        }
    }

    let encrypted = encryption::encrypt(&recipient, content).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(e.to_string(), "ENCRYPT_ERROR")),
        )
    })?;

    let chunked = encrypted
        .chunked()
        .expect("encrypt always returns ChunkedEncrypted");

    state.chunk_cache.insert(
        cache_key,
        CachedEncryption {
            payload: chunked.clone(),
            expires_at: Instant::now() + CHUNK_CACHE_TTL,
            content_hash: content_hash.clone(),
        },
    );

    Ok((chunked, content_hash))
}

/// File download endpoint - returns the full encrypted TransmissionFile (all chunks)
async fn file_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let client_id = authenticate_request(&state, &headers).await?;

    let (chunked, content_hash) = get_or_populate_cache(&state, &client_id, &path).await?;

    let body_content = encryption::Content::ChunkedEncrypted(chunked);
    let body_cbor = body_content.to_cbor();

    let (signature, timestamp) =
        encryption::sign(&state.server_signing_key, &body_cbor).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(e.to_string(), "SIGN_ERROR")),
            )
        })?;

    let transmission = encryption::TransmissionFile::new(timestamp, body_content, signature);
    let body = transmission.to_cbor();

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert("Content-Type", "application/octet-stream".parse().unwrap());
    resp_headers.insert("X-Content-Hash", content_hash.parse().unwrap());

    Ok((resp_headers, body))
}

/// Chunk manifest response
#[derive(Serialize)]
struct ChunkManifestResponse {
    chunk_count: u64,
    chunk_size: usize,
    ephemeral_public_key: String,
    file_nonce: String,
    content_hash: String,
    /// Base64 Ed25519 signature over (epk_hex || nonce_hex || chunk_count big-endian 8 bytes)
    signature: String,
    timestamp: i64,
}

/// Returns metadata about available chunks for resumable download
async fn chunk_manifest_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Result<Json<ChunkManifestResponse>, (StatusCode, Json<ErrorResponse>)> {
    let client_id = authenticate_request(&state, &headers).await?;

    let (chunked, content_hash) = get_or_populate_cache(&state, &client_id, &path).await?;

    let epk_hex = hex::encode(&chunked.ephemeral_public_key);
    let nonce_hex = hex::encode(&chunked.file_nonce);

    // Sign over epk_hex || nonce_hex || chunk_count (big-endian 8 bytes)
    let mut sign_payload = Vec::new();
    sign_payload.extend_from_slice(epk_hex.as_bytes());
    sign_payload.extend_from_slice(nonce_hex.as_bytes());
    sign_payload.extend_from_slice(&chunked.chunk_count.to_be_bytes());

    let (signature, timestamp) = encryption::sign(&state.server_signing_key, &sign_payload)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(e.to_string(), "SIGN_ERROR")),
            )
        })?;

    Ok(Json(ChunkManifestResponse {
        chunk_count: chunked.chunk_count,
        chunk_size: encryption::CHUNK_SIZE,
        ephemeral_public_key: epk_hex,
        file_nonce: nonce_hex,
        content_hash,
        signature: BASE64.encode(&signature),
        timestamp,
    }))
}

/// Returns raw ciphertext bytes for a single chunk
async fn chunk_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path((index, path)): Path<(u64, String)>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    let client_id = authenticate_request(&state, &headers).await?;

    let (chunked, _content_hash) = get_or_populate_cache(&state, &client_id, &path).await?;

    let chunk_data = chunked.chunks.get(index as usize).ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                format!("Chunk index {index} out of range"),
                "INVALID_CHUNK_INDEX",
            )),
        )
    })?;

    let mut resp_headers = HeaderMap::new();
    resp_headers.insert("Content-Type", "application/octet-stream".parse().unwrap());
    resp_headers.insert("X-Chunk-Index", index.to_string().parse().unwrap());
    resp_headers.insert(
        "X-Chunk-Count",
        chunked.chunk_count.to_string().parse().unwrap(),
    );

    Ok((resp_headers, chunk_data.clone()))
}

/// Authenticate a request using Ed25519 signature
async fn authenticate_request(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let client_id = headers
        .get("X-Client-Id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new(
                    "Missing X-Client-Id header",
                    "MISSING_CLIENT_ID",
                )),
            )
        })?;

    let timestamp_str = headers
        .get("X-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new(
                    "Missing X-Timestamp header",
                    "MISSING_TIMESTAMP",
                )),
            )
        })?;

    let timestamp: i64 = timestamp_str.parse().map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Invalid timestamp", "INVALID_TIMESTAMP")),
        )
    })?;

    let nonce = headers
        .get("X-Nonce")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new(
                    "Missing X-Nonce header",
                    "MISSING_NONCE",
                )),
            )
        })?;

    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new(
                    "Missing Authorization header",
                    "MISSING_AUTH",
                )),
            )
        })?;

    // Parse authorization header: "Age-Auth <signature>"
    let signature_b64 = auth_header.strip_prefix("Age-Auth ").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(
                "Invalid Authorization format",
                "INVALID_AUTH_FORMAT",
            )),
        )
    })?;

    let signature = BASE64.decode(signature_b64).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(
                "Invalid signature encoding",
                "INVALID_SIGNATURE",
            )),
        )
    })?;

    // Check timestamp is within acceptable window (5 minutes)
    let now = chrono::Utc::now().timestamp_millis();
    let window = 5 * 60 * 1000;
    if (now - timestamp).abs() > window {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(
                "Timestamp out of range",
                "TIMESTAMP_EXPIRED",
            )),
        ));
    }

    if !state
        .nonce_cache
        .check_and_mark(client_id, nonce, timestamp)
    {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Nonce already used", "NONCE_REUSED")),
        ));
    }

    let config = state.config.read().await;
    let client = config.clients.get(client_id).ok_or_else(|| {
        (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse::new(
                "Client not registered",
                "CLIENT_NOT_FOUND",
            )),
        )
    })?;

    let verifying_key_bytes = BASE64.decode(&client.auth_public_key).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Invalid client key",
                "INVALID_CLIENT_KEY",
            )),
        )
    })?;

    let verifying_key_array: [u8; 32] = verifying_key_bytes.try_into().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(
                "Invalid client key length",
                "INVALID_CLIENT_KEY",
            )),
        )
    })?;

    let verifying_key =
        encryption::VerifyingKey::from_bytes(&verifying_key_array).map_err(|_| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(
                    "Invalid client key",
                    "INVALID_CLIENT_KEY",
                )),
            )
        })?;

    let payload = format!("{}\n{}\n{}", client_id, timestamp, nonce);

    let valid = encryption::verify(&verifying_key, payload.as_bytes(), &signature, timestamp)
        .map_err(|e| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new(e.to_string(), "VERIFY_ERROR")),
            )
        })?;

    if !valid {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Invalid signature", "INVALID_SIGNATURE")),
        ));
    }

    Ok(client_id.to_string())
}

/// Client enrollment endpoint
async fn enroll_handler(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Json(request): Json<EnrollRequest>,
) -> Result<Json<EnrollResponse>, (StatusCode, Json<ErrorResponse>)> {
    let config = state.config.read().await;
    let enrollment_config = &config.server.enrollment;

    if !enrollment_config.enabled {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "Enrollment is disabled",
                "ENROLLMENT_DISABLED",
            )),
        ));
    }

    let is_localhost = addr.ip().is_loopback();
    let skip_token = enrollment_config.allow_localhost && is_localhost;
    drop(config);

    let mut token_store = state.token_store.write().await;
    let (client_id, groups) = if skip_token {
        let client_id = request.client_id.clone().ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(
                    "client_id required for localhost enrollment",
                    "MISSING_CLIENT_ID",
                )),
            )
        })?;
        let groups = request.groups.clone().ok_or_else(|| {
            (
                StatusCode::BAD_REQUEST,
                Json(ErrorResponse::new(
                    "groups required for localhost enrollment",
                    "MISSING_GROUPS",
                )),
            )
        })?;
        log::info!("Localhost enrollment for client: {}", client_id);
        (client_id, groups)
    } else {
        let token_entry = token_store.validate(&request.token_secret).ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new(
                    "Invalid or expired token",
                    "INVALID_TOKEN",
                )),
            )
        })?;
        (token_entry.client_id.clone(), token_entry.groups.clone())
    };

    // Decrypt the payload using server's X25519 identity
    let encrypted_payload = BASE64.decode(&request.encrypted_payload).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "Invalid payload encoding",
                "INVALID_PAYLOAD",
            )),
        )
    })?;

    // The client encrypts the payload and serializes it as Content CBOR.
    let content = encryption::Content::from_cbor(&encrypted_payload).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(e.to_string(), "INVALID_PAYLOAD_FORMAT")),
        )
    })?;

    let chunked = content.chunked().ok_or_else(|| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "Expected chunked encrypted payload",
                "INVALID_PAYLOAD_FORMAT",
            )),
        )
    })?;

    let decrypted = encryption::decrypt(&state.server_x25519_identity, &chunked).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(e.to_string(), "DECRYPT_ERROR")),
        )
    })?;

    let payload: EnrollPayload = serde_json::from_slice(&decrypted.into_inner()).map_err(|e| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(e.to_string(), "INVALID_JSON")),
        )
    })?;

    // Validate key format
    encryption::X25519Recipient::from_str(&payload.x25519_public_key).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new(
                "Invalid x25519 public key format",
                "INVALID_X25519_KEY",
            )),
        )
    })?;

    if !skip_token {
        token_store.mark_used(&request.token_secret);
    }

    let client_entry = ClientEntry {
        x25519_public_key: payload.x25519_public_key,
        auth_public_key: payload.auth_public_key,
        groups: groups.clone(),
        enrolled_at: Some(chrono::Utc::now().to_rfc3339()),
        binaries: vec![],
    };

    {
        let mut config = state.config.write().await;
        config
            .clients
            .insert(client_id.clone(), client_entry.clone());
    }

    append_client_to_config(&state.config_path, &client_id, &client_entry)
        .await
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(e.to_string(), "CONFIG_WRITE_ERROR")),
            )
        })?;

    log::info!("Enrolled new client: {client_id} with groups: {groups:?}",);

    Ok(Json(EnrollResponse { client_id, groups }))
}

/// Append a new client entry to the server config file
async fn append_client_to_config(
    config_path: &std::path::Path,
    client_id: &str,
    entry: &ClientEntry,
) -> anyhow::Result<()> {
    use tokio::io::AsyncWriteExt;

    let toml_entry = format!(
        r#"

# Auto-added by enrollment at {}
[clients.{client_id}]
x25519_public_key = "{}"
auth_public_key = "{}"
groups = {:?}
enrolled_at = "{}"
"#,
        entry.enrolled_at.as_ref().unwrap_or(&String::new()),
        entry.x25519_public_key,
        entry.auth_public_key,
        entry.groups,
        entry.enrolled_at.as_ref().unwrap_or(&String::new()),
    );

    let mut file = tokio::fs::OpenOptions::new()
        .append(true)
        .open(config_path)
        .await?;
    file.write_all(toml_entry.as_bytes()).await?;
    file.flush().await?;

    Ok(())
}

/// Start the web server
pub async fn run_server(state: AppState, bind: &str) -> anyhow::Result<()> {
    let router = create_router(state);

    let listener = tokio::net::TcpListener::bind(bind)
        .await
        .inspect_err(|e| log::error!("Web server bind error: {e:?}"))?;

    log::info!("Server listening on {bind}");

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::configure::{
        ClientEntry, EnrollmentConfig, GroupConfig, ServerKeyConfig, ServerSettings,
    };
    use crate::enrollment::TokenStore;
    use axum::body::Body;
    use axum::http::Request;
    use sha2::{Digest, Sha256};
    use std::collections::HashMap;
    use tower::ServiceExt;

    struct TestEnv {
        dir: tempfile::TempDir,
        state: AppState,
        client_signing_key: encryption::SigningKey,
        client_x25519_identity: encryption::X25519Identity,
        client_id: String,
    }

    impl TestEnv {
        fn new(file_name: &str, content: &[u8]) -> Self {
            let dir = tempfile::TempDir::new().unwrap();
            let file_path = dir.path().join(file_name);
            std::fs::write(&file_path, content).unwrap();

            let server_signing_key = encryption::SigningKey::generate();
            let server_x25519_identity = encryption::X25519Identity::generate();

            let client_signing_key = encryption::SigningKey::generate();
            let client_x25519_identity = encryption::X25519Identity::generate();
            let client_id = "test-client".to_string();

            let mut groups = HashMap::new();
            groups.insert(
                "test-group".to_string(),
                GroupConfig {
                    description: None,
                    paths: vec![file_path.to_string_lossy().to_string()],
                },
            );

            let mut clients = HashMap::new();
            clients.insert(
                client_id.clone(),
                ClientEntry {
                    x25519_public_key: client_x25519_identity.to_recipient().to_string(),
                    auth_public_key: BASE64.encode(client_signing_key.verifying_key().to_bytes()),
                    groups: vec!["test-group".to_string()],
                    enrolled_at: None,
                    binaries: vec![],
                },
            );

            let config = ServerConfig {
                version: 1,
                server: ServerSettings {
                    bind: "127.0.0.1:0".to_string(),
                    tls: None,
                    proxy: None,
                    keys: ServerKeyConfig {
                        signing_key_path: dir.path().join("unused.key"),
                        x25519_identity_path: dir.path().join("unused.x25519"),
                    },
                    enrollment: EnrollmentConfig {
                        enabled: false,
                        token_expiry_hours: 1,
                        allow_localhost: false,
                    },
                    admin: None,
                },
                clients,
                groups,
                binaries: HashMap::new(),
            };

            let state = AppState::new(
                config,
                server_signing_key,
                server_x25519_identity,
                TokenStore::new(),
                dir.path().join("unused.toml"),
            );

            Self {
                dir,
                state,
                client_signing_key,
                client_x25519_identity,
                client_id,
            }
        }

        fn auth_headers(&self) -> Vec<(&'static str, String)> {
            let timestamp = chrono::Utc::now().timestamp_millis();
            let nonce = BASE64.encode(rand::random::<[u8; 16]>());
            let payload = format!("{}\n{}\n{}", self.client_id, timestamp, nonce);
            let (sig, _) = encryption::sign(&self.client_signing_key, payload.as_bytes()).unwrap();
            vec![
                ("X-Client-Id", self.client_id.clone()),
                ("X-Timestamp", timestamp.to_string()),
                ("X-Nonce", nonce),
                ("Authorization", format!("Age-Auth {}", BASE64.encode(&sig))),
            ]
        }

        fn router(&self) -> axum::Router {
            create_router(self.state.clone())
        }

        fn file_path(&self, name: &str) -> std::path::PathBuf {
            self.dir.path().join(name)
        }

        /// Returns the relative path the server assigns to a file: "group_name:filename".
        fn relative_path(&self, name: &str) -> String {
            format!("test-group:{name}")
        }
    }

    fn make_request(method: &str, uri: &str, headers: &[(&'static str, String)]) -> Request<Body> {
        let mut builder = Request::builder().method(method).uri(uri);
        for (k, v) in headers {
            builder = builder.header(*k, v);
        }
        builder.body(Body::empty()).unwrap()
    }

    async fn body_bytes(resp: axum::response::Response) -> bytes::Bytes {
        axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap()
    }

    // Download a file via the chunked resumable API and return the assembled plaintext.
    async fn download_via_chunks(env: &TestEnv, path: &str) -> Vec<u8> {
        let router = env.router();

        // 1. Fetch chunk manifest
        let resp = router
            .clone()
            .oneshot(make_request(
                "GET",
                &format!("/api/v1/chunks/{path}"),
                &env.auth_headers(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK, "chunk manifest failed");
        let manifest: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();

        let chunk_count = manifest["chunk_count"].as_u64().unwrap();
        let epk_hex = manifest["ephemeral_public_key"]
            .as_str()
            .unwrap()
            .to_string();
        let nonce_hex = manifest["file_nonce"].as_str().unwrap().to_string();
        let content_hash = manifest["content_hash"].as_str().unwrap().to_string();

        let epk_bytes = hex::decode(&epk_hex).unwrap();
        let nonce_bytes = hex::decode(&nonce_hex).unwrap();

        // 2. Download and decrypt each chunk
        let mut plaintext = Vec::new();
        for i in 0..chunk_count {
            let resp = router
                .clone()
                .oneshot(make_request(
                    "GET",
                    &format!("/api/v1/chunk/{i}/{path}"),
                    &env.auth_headers(),
                ))
                .await
                .unwrap();
            assert_eq!(resp.status(), StatusCode::OK, "chunk {i} fetch failed");
            let ciphertext = body_bytes(resp).await.to_vec();

            let payload = encryption::ChunkedEncrypted {
                ephemeral_public_key: epk_bytes.clone(),
                file_nonce: nonce_bytes.clone(),
                chunk_count,
                chunks: {
                    let mut v: Vec<Vec<u8>> = (0..i).map(|_| vec![]).collect();
                    v.push(ciphertext);
                    v
                },
            };
            let chunk_plain =
                encryption::decrypt_chunk(&env.client_x25519_identity, &payload, i as usize)
                    .unwrap();
            plaintext.extend_from_slice(&chunk_plain);
        }

        // 3. Verify hash matches what manifest promised
        let actual_hash = format!("sha256:{}", hex::encode(Sha256::digest(&plaintext)));
        assert_eq!(
            actual_hash, content_hash,
            "assembled plaintext hash does not match manifest content_hash"
        );

        plaintext
    }

    #[tokio::test]
    async fn test_chunk_download_hash_matches_original() {
        let content = b"hello from the trust distribution system";
        let env = TestEnv::new("test.txt", content);
        let path = env.relative_path("test.txt");

        let downloaded = download_via_chunks(&env, &path).await;
        assert_eq!(downloaded, content);
    }

    #[tokio::test]
    async fn test_chunk_download_large_file_hash_matches() {
        // Larger than CHUNK_SIZE to exercise the multi-chunk path
        let content: Vec<u8> = (0..encryption::CHUNK_SIZE + 1024)
            .map(|i| (i % 251) as u8)
            .collect();
        let env = TestEnv::new("large.bin", &content);
        let path = env.relative_path("large.bin");

        let downloaded = download_via_chunks(&env, &path).await;
        assert_eq!(downloaded, content);
    }

    #[tokio::test]
    async fn test_manifest_hash_matches_chunk_download() {
        let content = b"manifest and chunk must agree on hash";
        let env = TestEnv::new("data.txt", content);
        let path = env.relative_path("data.txt");
        let router = env.router();

        // Fetch manifest
        let resp = router
            .clone()
            .oneshot(make_request("GET", "/api/v1/manifest", &env.auth_headers()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let manifest: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();

        let files = manifest["files"].as_array().unwrap();
        let entry = files
            .iter()
            .find(|f| f["path"].as_str() == Some(path.as_str()))
            .expect("data.txt not in manifest");
        let manifest_hash = entry["content_hash"].as_str().unwrap().to_string();

        // Download via chunks — download_via_chunks asserts chunk manifest hash matches plaintext.
        // Also assert it equals the file-level manifest hash.
        let downloaded = download_via_chunks(&env, &path).await;
        let actual_hash = format!("sha256:{}", hex::encode(Sha256::digest(&downloaded)));
        assert_eq!(
            actual_hash, manifest_hash,
            "chunk download hash does not match manifest-level hash"
        );
    }

    #[tokio::test]
    async fn test_updated_file_serves_new_content() {
        let env = TestEnv::new("update.txt", b"version one");
        let path = env.relative_path("update.txt");
        let router = env.router();

        // Download v1
        let v1 = download_via_chunks(&env, &path).await;
        assert_eq!(v1, b"version one");

        // Update file on disk
        std::fs::write(env.file_path("update.txt"), b"version two").unwrap();

        // Download again — must get v2, not the cached v1
        let resp = router
            .clone()
            .oneshot(make_request("GET", "/api/v1/manifest", &env.auth_headers()))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let manifest: serde_json::Value = serde_json::from_slice(&body_bytes(resp).await).unwrap();
        let files = manifest["files"].as_array().unwrap();
        let entry = files
            .iter()
            .find(|f| f["path"].as_str() == Some(path.as_str()))
            .expect("update.txt not in manifest");
        let new_hash = entry["content_hash"].as_str().unwrap();
        let expected_hash = format!("sha256:{}", hex::encode(Sha256::digest(b"version two")));
        assert_eq!(
            new_hash, expected_hash,
            "manifest did not reflect updated file"
        );

        let v2 = download_via_chunks(&env, &path).await;
        assert_eq!(
            v2, b"version two",
            "chunk download still serving stale content"
        );
    }
}
