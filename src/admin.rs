use axum::{
    Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};

use crate::configure::AdminConfig;
use crate::enrollment::{TokenEntry, generate_token};
use crate::types::{AppState, ErrorResponse};

/// Request to create enrollment tokens
#[derive(Debug, Deserialize)]
pub struct AdminTokenRequest {
    pub client_id: String,
    pub groups: Vec<String>,
    #[serde(default = "default_count")]
    pub count: u32,
    pub expiry_hours: Option<u32>,
}

fn default_count() -> u32 {
    1
}

/// Response containing created tokens
#[derive(Debug, Serialize)]
pub struct AdminTokenResponse {
    pub tokens: Vec<TokenInfo>,
    pub count: u32,
}

/// Info about a single generated token
#[derive(Debug, Serialize)]
pub struct TokenInfo {
    pub token: String,
    pub client_id: String,
    pub groups: Vec<String>,
    pub expires_at: String,
}

/// Response for listing tokens
#[derive(Debug, Serialize)]
pub struct AdminTokenListResponse {
    pub tokens: Vec<TokenListEntry>,
    pub count: usize,
}

/// Entry in token list
#[derive(Debug, Serialize)]
pub struct TokenListEntry {
    pub client_id: String,
    pub groups: Vec<String>,
    pub created_at: String,
    pub expires_at: String,
}

impl From<&TokenEntry> for TokenListEntry {
    fn from(entry: &TokenEntry) -> Self {
        Self {
            client_id: entry.client_id.clone(),
            groups: entry.groups.clone(),
            created_at: entry.created_at_string(),
            expires_at: entry.expires_at_string(),
        }
    }
}

/// Validate admin credentials (password + TOTP)
fn validate_admin_auth(
    admin_config: &AdminConfig,
    password: &str,
    totp_code: &str,
) -> Result<(), &'static str> {
    use argon2::{Argon2, PasswordHash, PasswordVerifier};
    use totp_rs::{Algorithm, TOTP};

    // 1. Verify password with Argon2
    let parsed_hash = PasswordHash::new(&admin_config.password_hash)
        .map_err(|_| "Invalid password hash in config")?;

    Argon2::default()
        .verify_password(password.as_bytes(), &parsed_hash)
        .map_err(|_| "Invalid password")?;

    // 2. Verify TOTP code
    let secret_bytes = data_encoding::BASE32_NOPAD
        .decode(admin_config.totp_secret.to_uppercase().as_bytes())
        .map_err(|_| "Invalid TOTP secret in config")?;

    let totp = TOTP::new(
        Algorithm::SHA1,
        6,
        1, // skew: allow 1 step variance (30 seconds)
        30,
        secret_bytes,
    )
    .map_err(|_| "Failed to create TOTP validator")?;

    if !totp.check_current(totp_code).unwrap_or(false) {
        return Err("Invalid TOTP code");
    }

    Ok(())
}

/// Extract and validate admin auth from headers
fn extract_admin_auth(
    headers: &HeaderMap,
) -> Result<(String, String), (StatusCode, Json<ErrorResponse>)> {
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

    let password = auth_header.strip_prefix("Admin ").ok_or_else(|| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(
                "Invalid Authorization format, expected 'Admin <password>'",
                "INVALID_AUTH_FORMAT",
            )),
        )
    })?;

    let totp_code = headers
        .get("X-TOTP-Code")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            (
                StatusCode::UNAUTHORIZED,
                Json(ErrorResponse::new(
                    "Missing X-TOTP-Code header",
                    "MISSING_TOTP",
                )),
            )
        })?;

    Ok((password.to_string(), totp_code.to_string()))
}

/// Authenticate admin request
async fn authenticate_admin(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<(), (StatusCode, Json<ErrorResponse>)> {
    let (password, totp_code) = extract_admin_auth(headers)?;

    let config = state.config.read().await;
    let admin_config = config.server.admin.as_ref().ok_or_else(|| {
        (
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(
                "Admin endpoint not configured",
                "ADMIN_DISABLED",
            )),
        )
    })?;

    validate_admin_auth(admin_config, &password, &totp_code).map_err(|e| {
        (
            StatusCode::UNAUTHORIZED,
            Json(ErrorResponse::new(e, "AUTH_FAILED")),
        )
    })
}

/// POST /api/v1/admin/tokens - Create enrollment token(s)
pub async fn admin_create_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(request): Json<AdminTokenRequest>,
) -> Result<(StatusCode, Json<AdminTokenResponse>), (StatusCode, Json<ErrorResponse>)> {
    authenticate_admin(&state, &headers).await?;

    // Get config values
    let config = state.config.read().await;
    let expiry_hours = request
        .expiry_hours
        .unwrap_or(config.server.enrollment.token_expiry_hours);
    let server_age_recipient = state.server_age_identity.to_recipient().to_string();
    let server_verify_key = BASE64.encode(state.server_signing_key.verifying_key().to_bytes());
    drop(config);

    // Cap at 10 tokens per request
    let count = request.count.min(10).max(1);

    let mut token_store = state.token_store.write().await;
    let mut tokens = Vec::with_capacity(count as usize);

    for i in 0..count {
        let client_id = if count > 1 {
            format!("{}-{}", request.client_id, i + 1)
        } else {
            request.client_id.clone()
        };

        let (token, entry) = generate_token(
            &client_id,
            &request.groups,
            &server_age_recipient,
            &server_verify_key,
            expiry_hours,
        );

        tokens.push(TokenInfo {
            token,
            client_id: client_id.clone(),
            groups: request.groups.clone(),
            expires_at: entry.expires_at_string(),
        });

        token_store.add(entry);
    }

    log::info!(
        "Admin created {} token(s) for client_id pattern: {}",
        count,
        request.client_id
    );

    Ok((
        StatusCode::CREATED,
        Json(AdminTokenResponse { tokens, count }),
    ))
}

/// GET /api/v1/admin/tokens - List pending tokens
pub async fn admin_list_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> Result<Json<AdminTokenListResponse>, (StatusCode, Json<ErrorResponse>)> {
    authenticate_admin(&state, &headers).await?;

    let token_store = state.token_store.read().await;
    let pending = token_store.pending();

    let tokens: Vec<TokenListEntry> = pending.iter().map(|e| TokenListEntry::from(*e)).collect();
    let count = tokens.len();

    Ok(Json(AdminTokenListResponse { tokens, count }))
}

/// DELETE /api/v1/admin/tokens/:client_id - Revoke tokens for a client
pub async fn admin_revoke_tokens(
    State(state): State<AppState>,
    headers: HeaderMap,
    axum::extract::Path(client_id): axum::extract::Path<String>,
) -> Result<StatusCode, (StatusCode, Json<ErrorResponse>)> {
    authenticate_admin(&state, &headers).await?;

    let mut token_store = state.token_store.write().await;

    if token_store.revoke(&client_id) {
        log::info!("Admin revoked token(s) for client_id: {}", client_id);
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err((
            StatusCode::NOT_FOUND,
            Json(ErrorResponse::new(
                format!("No pending token found for '{}'", client_id),
                "TOKEN_NOT_FOUND",
            )),
        ))
    }
}

/// Generate current TOTP code from a secret (for CLI utility)
pub fn generate_totp_code(secret: &str) -> anyhow::Result<String> {
    use totp_rs::{Algorithm, TOTP};

    let secret_bytes = data_encoding::BASE32_NOPAD
        .decode(secret.to_uppercase().as_bytes())
        .map_err(|e| anyhow::anyhow!("Invalid TOTP secret: {}", e))?;

    let totp = TOTP::new(Algorithm::SHA1, 6, 1, 30, secret_bytes)
        .map_err(|e| anyhow::anyhow!("Failed to create TOTP: {}", e))?;

    totp.generate_current()
        .map_err(|e| anyhow::anyhow!("Failed to generate TOTP code: {}", e))
}

/// Generate Argon2id password hash (for CLI utility)
pub fn hash_password(password: &str) -> anyhow::Result<String> {
    use argon2::password_hash::SaltString;
    use argon2::password_hash::rand_core::OsRng;
    use argon2::{Argon2, PasswordHasher};

    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();

    let hash = argon2
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Failed to hash password: {}", e))?;

    Ok(hash.to_string())
}

/// Generate new TOTP secret for setup (for CLI utility)
pub fn generate_totp_secret() -> String {
    use rand::Rng;
    let secret: [u8; 20] = rand::thread_rng().r#gen();
    data_encoding::BASE32_NOPAD.encode(&secret)
}
