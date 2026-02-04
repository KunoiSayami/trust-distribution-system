use anyhow::{Context, anyhow};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::path::PathBuf;

use crate::config::ClientConfig;

/// Manifest response from server
#[derive(Debug, Deserialize)]
pub struct ManifestResponse {
    #[allow(unused)]
    pub version: u32,
    pub timestamp: i64,
    pub files: Vec<ManifestFileEntry>,
    pub signature: String,
}

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct ManifestFileEntry {
    pub path: String,
    pub content_hash: String,
    pub size: u64,
    pub group: String,
    /// File modification timestamp (Unix seconds)
    #[serde(default)]
    pub modified_at: i64,
}

/// Tracked metadata for a synced file
#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct FileMetadata {
    /// Content hash from server (for verification)
    pub content_hash: String,
    /// Modification timestamp from server (Unix seconds)
    pub modified_at: i64,
}

/// Persistent state for tracking downloaded files
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct SyncState {
    /// Legacy: Map of file path -> content hash (for backward compatibility)
    #[serde(default)]
    pub file_hashes: HashMap<String, String>,
    /// Map of file path -> file metadata (modification time + hash)
    #[serde(default)]
    pub file_metadata: HashMap<String, FileMetadata>,
    /// Last successful sync timestamp
    pub last_sync: Option<i64>,
}

impl SyncState {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        if path.exists() {
            let content = std::fs::read_to_string(path)?;
            Ok(serde_json::from_str(&content)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, path: &std::path::Path) -> anyhow::Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }
}

/// HTTP client with Ed25519 authentication
pub struct TdsClient {
    client: Client,
    server_url: String,
    client_id: String,
    signing_key: encryption::SigningKey,
    server_verify_key: encryption::VerifyingKey,
    age_identity: encryption::AgeIdentity,
}

impl TdsClient {
    pub fn new(
        server_url: String,
        client_id: String,
        signing_key: encryption::SigningKey,
        server_verify_key: encryption::VerifyingKey,
        age_identity: encryption::AgeIdentity,
    ) -> anyhow::Result<Self> {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(300))
            .build()?;

        Ok(Self {
            client,
            server_url,
            client_id,
            signing_key,
            server_verify_key,
            age_identity,
        })
    }

    /// Generate authentication headers for a request
    fn auth_headers(&self) -> anyhow::Result<Vec<(String, String)>> {
        let timestamp = chrono::Utc::now().timestamp_millis();
        let nonce = BASE64.encode(rand::random::<[u8; 16]>());

        // Payload to sign: client_id || "\n" || timestamp || "\n" || nonce
        let payload = format!("{}\n{}\n{}", self.client_id, timestamp, nonce);

        // Sign the payload
        let (signature, _) = encryption::sign(&self.signing_key, payload.as_bytes())?;

        Ok(vec![
            ("X-Client-Id".to_string(), self.client_id.clone()),
            ("X-Timestamp".to_string(), timestamp.to_string()),
            ("X-Nonce".to_string(), nonce),
            (
                "Authorization".to_string(),
                format!("Age-Auth {}", BASE64.encode(&signature)),
            ),
        ])
    }

    /// Fetch the manifest from the server
    pub async fn fetch_manifest(&self) -> anyhow::Result<ManifestResponse> {
        let url = format!("{}/api/v1/manifest", self.server_url);
        let headers = self.auth_headers()?;

        let mut request = self.client.get(&url);
        for (key, value) in headers {
            request = request.header(&key, &value);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Server error {}: {}", status, body));
        }

        let manifest: ManifestResponse = response.json().await?;

        // Verify manifest signature
        let manifest_data = serde_json::to_vec(&manifest.files)?;
        let signature = BASE64
            .decode(&manifest.signature)
            .context("Invalid manifest signature encoding")?;

        let valid = encryption::verify(
            &self.server_verify_key,
            &manifest_data,
            &signature,
            manifest.timestamp,
        )?;
        if !valid {
            return Err(anyhow!("Invalid manifest signature"));
        }

        Ok(manifest)
    }

    /// Download and decrypt a file from the server
    pub async fn download_file(&self, path: &str) -> anyhow::Result<Vec<u8>> {
        let url = format!("{}/api/v1/files/{}", self.server_url, path);
        let headers = self.auth_headers()?;

        let mut request = self.client.get(&url);
        for (key, value) in headers {
            request = request.header(&key, &value);
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            let status = response.status();
            let body = response.text().await.unwrap_or_default();
            return Err(anyhow!("Server error {status}: {body}"));
        }

        // Get expected hash from header
        let expected_hash = response
            .headers()
            .get("X-Content-Hash")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let body = response.bytes().await?;

        // Parse CBOR transmission file
        let transmission = encryption::TransmissionFile::from_cbor(&body)
            .context("Failed to parse transmission file")?;

        // Verify signature
        let encrypted_bytes = match transmission.body() {
            encryption::Content::Encrypted(data) => data,
            encryption::Content::Plain(_) => return Err(anyhow!("Expected encrypted content")),
        };

        let valid = encryption::verify(
            &self.server_verify_key,
            encrypted_bytes,
            transmission.signature(),
            transmission.timestamp(),
        )?;
        if !valid {
            return Err(anyhow!("Invalid file signature"));
        }

        // Decrypt the content
        let decrypted = encryption::decrypt(&self.age_identity, encrypted_bytes.clone())?;
        let plain_bytes = decrypted.into_inner();

        // Verify hash if provided
        if let Some(expected) = expected_hash {
            let actual_hash = format!("sha256:{}", hex::encode(Sha256::digest(&plain_bytes)));
            if actual_hash != expected {
                return Err(anyhow!(
                    "Hash mismatch: expected {expected}, got {actual_hash}",
                ));
            }
        }

        Ok(plain_bytes)
    }
}

/// Determine which files need to be downloaded
pub fn files_to_download(
    manifest: &ManifestResponse,
    state: &SyncState,
    subscribed_groups: &[String],
) -> Vec<ManifestFileEntry> {
    manifest
        .files
        .iter()
        .filter(|file| {
            // Only download files from subscribed groups
            if !subscribed_groups.contains(&file.group) {
                return false;
            }

            // Check if server's file metadata has changed since last sync
            match state.file_metadata.get(&file.path) {
                Some(existing) => {
                    // Download if modification time changed (primary check)
                    // or if hash changed (fallback for edge cases)
                    existing.modified_at != file.modified_at
                        || existing.content_hash != file.content_hash
                }
                None => {
                    // New file, or migrating from old state format
                    // Also check legacy file_hashes for migration scenario
                    match state.file_hashes.get(&file.path) {
                        Some(existing_hash) => existing_hash != &file.content_hash,
                        None => true, // Truly new file
                    }
                }
            }
        })
        .cloned()
        .collect()
}

/// Determine the output path for a file
pub fn get_output_path(file: &ManifestFileEntry, config: &ClientConfig) -> Option<PathBuf> {
    let subscription = config.subscriptions.get(&file.group)?;

    // Get the filename, handling potential renames
    let filename = std::path::Path::new(&file.path)
        .file_name()
        .map(|n| n.to_string_lossy().to_string())
        .unwrap_or_else(|| file.path.clone());

    let final_name = subscription
        .rename
        .get(&filename)
        .cloned()
        .unwrap_or(filename);

    let path = if subscription.preserve_structure {
        // Preserve directory structure
        let parent = std::path::Path::new(&file.path).parent();
        match parent {
            Some(p) if !p.as_os_str().is_empty() => {
                subscription.output_directory.join(p).join(&final_name)
            }
            _ => subscription.output_directory.join(&final_name),
        }
    } else {
        // Flat structure
        subscription.output_directory.join(&final_name)
    };

    Some(path)
}
