use std::net::SocketAddr;

use axum::{
    Router,
    extract::{ConnectInfo, Path, State},
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{delete, get, post},
    Json,
};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use sha2::{Digest, Sha256};

use crate::admin;
use crate::configure::ClientEntry;
use crate::types::{
    AppState, EnrollPayload, EnrollRequest, EnrollResponse, ErrorResponse, HealthResponse,
    ManifestFileEntry, ManifestResponse,
};

/// Create the router with all API endpoints
pub fn create_router(state: AppState) -> Router {
    Router::new()
        .route("/api/v1/health", get(health_handler))
        .route("/api/v1/manifest", get(manifest_handler))
        .route("/api/v1/files/*path", get(file_handler))
        .route("/api/v1/enroll", post(enroll_handler))
        // Admin endpoints
        .route("/api/v1/admin/tokens", post(admin::admin_create_tokens))
        .route("/api/v1/admin/tokens", get(admin::admin_list_tokens))
        .route("/api/v1/admin/tokens/:client_id", delete(admin::admin_revoke_tokens))
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
    // Authenticate the request
    let client_id = authenticate_request(&state, &headers).await?;

    // Get files for this client
    let config = state.config.read().await;
    let files = config.get_client_files(&client_id);

    // Build manifest entries
    let mut entries = Vec::new();
    for file_info in files {
        if let Ok(content) = tokio::fs::read(&file_info.source_path).await {
            let hash = format!("sha256:{}", hex::encode(Sha256::digest(&content)));
            entries.push(ManifestFileEntry {
                path: file_info.relative_path,
                content_hash: hash,
                size: content.len() as u64,
                group: file_info.group,
            });
        }
    }

    let timestamp = chrono::Utc::now().timestamp_millis();

    // Sign the manifest
    let manifest_data = serde_json::to_vec(&entries).unwrap_or_default();
    let (signature, _) = encryption::sign(&state.server_signing_key, &manifest_data)
        .map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(e.to_string(), "SIGN_ERROR")),
            )
        })?;

    Ok(Json(ManifestResponse {
        version: 1,
        timestamp,
        files: entries,
        signature: BASE64.encode(&signature),
    }))
}

/// File download endpoint - returns encrypted file
async fn file_handler(
    State(state): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
) -> Result<impl IntoResponse, (StatusCode, Json<ErrorResponse>)> {
    // Authenticate the request
    let client_id = authenticate_request(&state, &headers).await?;

    // Get client's age recipient for encryption
    let config = state.config.read().await;
    let client = config.clients.get(&client_id).ok_or_else(|| {
        (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse::new("Client not found", "CLIENT_NOT_FOUND")),
        )
    })?;

    let recipient = encryption::AgeRecipient::from_str(&client.age_public_key).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(e.to_string(), "INVALID_RECIPIENT")),
        )
    })?;

    // Find the file
    let files = config.get_client_files(&client_id);
    let file_info = files.iter().find(|f| f.relative_path == path).ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new("File not found", "FILE_NOT_FOUND")),
        )
    })?;

    // Read and encrypt the file
    let content = tokio::fs::read(&file_info.source_path).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(e.to_string(), "READ_ERROR")),
        )
    })?;

    let content_hash = format!("sha256:{}", hex::encode(Sha256::digest(&content)));

    // Encrypt for this client
    let encrypted = encryption::encrypt(&recipient, content).map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(e.to_string(), "ENCRYPT_ERROR")),
        )
    })?;

    let encrypted_bytes = encrypted.into_inner();

    // Sign the encrypted content
    let (signature, timestamp) =
        encryption::sign(&state.server_signing_key, &encrypted_bytes).map_err(|e| {
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(ErrorResponse::new(e.to_string(), "SIGN_ERROR")),
            )
        })?;

    // Create transmission file
    let transmission = encryption::TransmissionFile::new(
        timestamp,
        encryption::Content::Encrypted(encrypted_bytes),
        signature,
    );

    let body = transmission.to_cbor();

    // Return with headers
    let mut headers = HeaderMap::new();
    headers.insert("Content-Type", "application/octet-stream".parse().unwrap());
    headers.insert("X-Content-Hash", content_hash.parse().unwrap());

    Ok((headers, body))
}

/// Authenticate a request using Ed25519 signature
async fn authenticate_request(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    // Extract required headers
    let client_id = headers
        .get("X-Client-Id")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new("Missing X-Client-Id header", "MISSING_CLIENT_ID")),
            )
        })?;

    let timestamp_str = headers
        .get("X-Timestamp")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new("Missing X-Timestamp header", "MISSING_TIMESTAMP")),
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
                Json(ErrorResponse::new("Missing X-Nonce header", "MISSING_NONCE")),
            )
        })?;

    let auth_header = headers
        .get("Authorization")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new("Missing Authorization header", "MISSING_AUTH")),
            )
        })?;

    // Parse authorization header: "Age-Auth <signature>"
    let signature_b64 = auth_header.strip_prefix("Age-Auth ").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Invalid Authorization format", "INVALID_AUTH_FORMAT")),
        )
    })?;

    let signature = BASE64.decode(signature_b64).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Invalid signature encoding", "INVALID_SIGNATURE")),
        )
    })?;

    // Check timestamp is within acceptable window (5 minutes)
    let now = chrono::Utc::now().timestamp_millis();
    let window = 5 * 60 * 1000; // 5 minutes in ms
    if (now - timestamp).abs() > window {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Timestamp out of range", "TIMESTAMP_EXPIRED")),
        ));
    }

    // Check nonce hasn't been used
    if !state.nonce_cache.check_and_mark(client_id, nonce, timestamp) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new("Nonce already used", "NONCE_REUSED")),
        ));
    }

    // Get client's public key
    let config = state.config.read().await;
    let client = config.clients.get(client_id).ok_or_else(|| {
        (
            StatusCode::FORBIDDEN,
            Json(ErrorResponse::new("Client not registered", "CLIENT_NOT_FOUND")),
        )
    })?;

    // Parse the client's verifying key
    let verifying_key_bytes = BASE64.decode(&client.auth_public_key).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Invalid client key", "INVALID_CLIENT_KEY")),
        )
    })?;

    let verifying_key_array: [u8; 32] = verifying_key_bytes.try_into().map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Invalid client key length", "INVALID_CLIENT_KEY")),
        )
    })?;

    let verifying_key = encryption::VerifyingKey::from_bytes(&verifying_key_array).map_err(|_| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new("Invalid client key", "INVALID_CLIENT_KEY")),
        )
    })?;

    // Reconstruct the signing payload
    // payload = client_id || "\n" || timestamp || "\n" || nonce
    let payload = format!("{}\n{}\n{}", client_id, timestamp, nonce);

    // Verify signature
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
    // Check if enrollment is enabled
    let config = state.config.read().await;
    let enrollment_config = &config.server.enrollment;

    if !enrollment_config.enabled {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Enrollment is disabled", "ENROLLMENT_DISABLED")),
        ));
    }

    // Check if localhost bypass is allowed
    let is_localhost = addr.ip().is_loopback();
    let skip_token = enrollment_config.allow_localhost && is_localhost;
    drop(config); // Release read lock before acquiring write lock

    // Validate token (unless localhost bypass)
    let mut token_store = state.token_store.write().await;
    let (client_id, groups) = if skip_token {
        // Localhost enrollment without token - require client_id and groups in request
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
        // Normal token-based enrollment
        let token_entry = token_store.validate(&request.token_secret).ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new("Invalid or expired token", "INVALID_TOKEN")),
            )
        })?;
        (token_entry.client_id.clone(), token_entry.groups.clone())
    };

    // Decrypt the payload using server's age identity
    let encrypted_payload = BASE64.decode(&request.encrypted_payload).map_err(|_| {
        (
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Invalid payload encoding", "INVALID_PAYLOAD")),
        )
    })?;

    let decrypted = encryption::decrypt(&state.server_age_identity, encrypted_payload).map_err(|e| {
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

    // Validate the keys format
    if !payload.age_public_key.starts_with("age1") {
        return Err((
            StatusCode::BAD_REQUEST,
            Json(ErrorResponse::new("Invalid age public key format", "INVALID_AGE_KEY")),
        ));
    }

    // Mark token as used (only for token-based enrollment)
    if !skip_token {
        token_store.mark_used(&request.token_secret);
        // Token store is in-memory only, no persistence needed
    }

    // Add client to config
    let client_entry = ClientEntry {
        age_public_key: payload.age_public_key,
        auth_public_key: payload.auth_public_key,
        groups: groups.clone(),
        enrolled_at: Some(chrono::Utc::now().to_rfc3339()),
    };

    // Update in-memory config
    {
        let mut config = state.config.write().await;
        config.clients.insert(client_id.clone(), client_entry.clone());
    }

    // Append to config file
    append_client_to_config(&state.config_path, &client_id, &client_entry).await.map_err(|e| {
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ErrorResponse::new(e.to_string(), "CONFIG_WRITE_ERROR")),
        )
    })?;

    log::info!("Enrolled new client: {} with groups: {:?}", client_id, groups);

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
[clients.{}]
age_public_key = "{}"
auth_public_key = "{}"
groups = {:?}
enrolled_at = "{}"
"#,
        entry.enrolled_at.as_ref().unwrap_or(&String::new()),
        client_id,
        entry.age_public_key,
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

    log::info!("Server listening on {}", bind);

    axum::serve(
        listener,
        router.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}
