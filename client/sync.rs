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

/// Chunk manifest returned by /chunks endpoint
#[derive(Debug, Deserialize, Clone)]
pub struct ChunkManifestResponse {
    pub chunk_count: u64,
    pub chunk_size: usize,
    pub ephemeral_public_key: String,
    pub file_nonce: String,
    pub content_hash: String,
    pub signature: String,
    pub timestamp: i64,
}

/// Progress tracking for a resumable download
#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq)]
pub struct ChunkProgress {
    pub chunk_count: u64,
    /// Sorted list of verified chunk indices
    pub verified_chunks: Vec<u64>,
    /// Ephemeral public key hex — used to detect server re-encryption
    pub ephemeral_public_key: String,
    pub file_nonce: String,
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
    /// In-progress chunked downloads
    #[serde(default)]
    pub chunk_progress: HashMap<String, ChunkProgress>,
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
    x25519_identity: encryption::X25519Identity,
}

impl TdsClient {
    pub fn new(
        server_url: String,
        client_id: String,
        signing_key: encryption::SigningKey,
        server_verify_key: encryption::VerifyingKey,
        x25519_identity: encryption::X25519Identity,
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
            x25519_identity,
        })
    }

    /// Generate authentication headers for a request
    fn auth_headers(&self) -> anyhow::Result<Vec<(String, String)>> {
        let timestamp = chrono::Utc::now().timestamp_millis();
        let nonce = BASE64.encode(rand::random::<[u8; 16]>());

        let payload = format!("{}\n{}\n{}", self.client_id, timestamp, nonce);
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

    /// Fetch the chunk manifest for a file (for resumable download)
    pub async fn fetch_chunk_manifest(&self, path: &str) -> anyhow::Result<ChunkManifestResponse> {
        let url = format!("{}/api/v1/files/{}/chunks", self.server_url, path);
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

        let manifest: ChunkManifestResponse = response.json().await?;

        // Verify manifest signature over (epk_hex || nonce_hex || chunk_count_be8)
        let mut sign_payload = Vec::new();
        sign_payload.extend_from_slice(manifest.ephemeral_public_key.as_bytes());
        sign_payload.extend_from_slice(manifest.file_nonce.as_bytes());
        sign_payload.extend_from_slice(&manifest.chunk_count.to_be_bytes());

        let sig_bytes = BASE64
            .decode(&manifest.signature)
            .context("Invalid chunk manifest signature encoding")?;
        let valid = encryption::verify(
            &self.server_verify_key,
            &sign_payload,
            &sig_bytes,
            manifest.timestamp,
        )?;
        if !valid {
            return Err(anyhow!("Invalid chunk manifest signature"));
        }

        Ok(manifest)
    }

    /// Download and decrypt a single chunk. Returns the decrypted plaintext bytes.
    #[allow(dead_code)]
    pub async fn download_chunk(
        &self,
        path: &str,
        chunk_index: u64,
        manifest: &ChunkManifestResponse,
    ) -> anyhow::Result<Vec<u8>> {
        let url = format!(
            "{}/api/v1/files/{}/chunk/{}",
            self.server_url, path, chunk_index
        );
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

        let ciphertext = response.bytes().await?.to_vec();

        // Build a minimal ChunkedEncrypted with just this one chunk so decrypt_chunk works
        let epk_bytes = hex::decode(&manifest.ephemeral_public_key)
            .context("Invalid ephemeral_public_key hex")?;
        let nonce_bytes = hex::decode(&manifest.file_nonce).context("Invalid file_nonce hex")?;

        let payload = encryption::ChunkedEncrypted {
            ephemeral_public_key: epk_bytes,
            file_nonce: nonce_bytes,
            chunk_count: manifest.chunk_count,
            chunks: {
                // Pad with empty vecs up to chunk_index, then put the ciphertext
                let mut v: Vec<Vec<u8>> = (0..chunk_index).map(|_| vec![]).collect();
                v.push(ciphertext);
                v
            },
        };

        encryption::decrypt_chunk(&self.x25519_identity, &payload, chunk_index as usize)
            .with_context(|| format!("Failed to decrypt chunk {chunk_index}"))
    }

    /// Download a file using chunked resumable transfer.
    /// Writes the decrypted content to `output_path` atomically on completion.
    /// Saves progress to `state` after each verified chunk.
    pub async fn download_file_resumable(
        &self,
        path: &str,
        state: &mut SyncState,
        state_path: &std::path::Path,
        output_path: &std::path::Path,
    ) -> anyhow::Result<Vec<u8>> {
        let manifest = self.fetch_chunk_manifest(path).await?;

        // Determine if we can resume or must start fresh
        let progress = state.chunk_progress.get(path).cloned();
        let resume = progress
            .as_ref()
            .map(|p| p.ephemeral_public_key == manifest.ephemeral_public_key)
            .unwrap_or(false);

        let mut verified: Vec<u64> = if resume {
            progress.unwrap().verified_chunks.clone()
        } else {
            Vec::new()
        };

        // Update progress entry with manifest info
        state.chunk_progress.insert(
            path.to_string(),
            ChunkProgress {
                chunk_count: manifest.chunk_count,
                verified_chunks: verified.clone(),
                ephemeral_public_key: manifest.ephemeral_public_key.clone(),
                file_nonce: manifest.file_nonce.clone(),
            },
        );

        let tmp_path = output_path.with_extension("tds-tmp");

        // Pre-allocate the temp file
        {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .write(true)
                .open(&tmp_path)?;
            let total_size = manifest.chunk_count as u64 * manifest.chunk_size as u64;
            file.set_len(total_size)?;
        }

        // Download missing chunks
        let epk_bytes = hex::decode(&manifest.ephemeral_public_key)?;
        let nonce_bytes = hex::decode(&manifest.file_nonce)?;

        let mut all_chunks: Vec<Option<Vec<u8>>> = vec![None; manifest.chunk_count as usize];

        // Fill already-verified slots as sentinel (we'll read from tmp file)
        for &idx in &verified {
            if (idx as usize) < all_chunks.len() {
                all_chunks[idx as usize] = Some(vec![]); // sentinel: already on disk
            }
        }

        for chunk_index in 0..manifest.chunk_count {
            if verified.contains(&chunk_index) {
                continue;
            }

            let url = format!(
                "{}/api/v1/files/{}/chunk/{}",
                self.server_url, path, chunk_index
            );
            let headers = self.auth_headers()?;
            let mut request = self.client.get(&url);
            for (key, value) in headers {
                request = request.header(&key, &value);
            }

            let response = request.send().await?;
            if !response.status().is_success() {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                return Err(anyhow!(
                    "Server error fetching chunk {chunk_index}: {status} {body}"
                ));
            }

            let ciphertext = response.bytes().await?.to_vec();

            // Decrypt
            let tmp_payload = encryption::ChunkedEncrypted {
                ephemeral_public_key: epk_bytes.clone(),
                file_nonce: nonce_bytes.clone(),
                chunk_count: manifest.chunk_count,
                chunks: {
                    let mut v: Vec<Vec<u8>> = (0..chunk_index).map(|_| vec![]).collect();
                    v.push(ciphertext);
                    v
                },
            };

            let plaintext = encryption::decrypt_chunk(
                &self.x25519_identity,
                &tmp_payload,
                chunk_index as usize,
            )
            .with_context(|| format!("Failed to decrypt chunk {chunk_index}"))?;

            // Write chunk to correct offset in temp file
            use std::io::{Seek, SeekFrom, Write};
            let mut file = std::fs::OpenOptions::new().write(true).open(&tmp_path)?;
            file.seek(SeekFrom::Start(chunk_index * manifest.chunk_size as u64))?;
            file.write_all(&plaintext)?;

            all_chunks[chunk_index as usize] = Some(plaintext);

            // Mark verified and persist state immediately
            verified.push(chunk_index);
            verified.sort_unstable();
            state.chunk_progress.insert(
                path.to_string(),
                ChunkProgress {
                    chunk_count: manifest.chunk_count,
                    verified_chunks: verified.clone(),
                    ephemeral_public_key: manifest.ephemeral_public_key.clone(),
                    file_nonce: manifest.file_nonce.clone(),
                },
            );
            state.save(state_path)?;
        }

        // All chunks verified — reassemble and verify hash
        // Read back from temp file (handles the resume case where some chunks were on disk)
        let full_content = std::fs::read(&tmp_path)?;

        // Trim trailing zeros from pre-allocation (last chunk may be shorter)
        // The actual size = sum of decrypted chunk sizes, which we derive from the content hash.
        // For simplicity we verify the sha256 hash from the manifest to confirm correctness.
        let actual_hash = format!("sha256:{}", hex::encode(Sha256::digest(&full_content)));
        // Note: the manifest.content_hash is sha256 of the plaintext before trailing trim.
        // We store both trimmed and full and pick based on hash match.
        // The correct approach: the last chunk's actual size tells us total size.
        // We already wrote decrypted bytes at the right offsets so trailing zeros are padding.
        // Re-read using the known plaintext size from chunk sizes.
        //
        // Simpler: trust that the hash matches if we truncate to the last written byte.
        // Find the last non-zero byte (or use the actual total from chunk sizes).
        // Since chunk sizes vary only for the last chunk, we use the content hash to validate.
        let content_hash = &manifest.content_hash;

        // Try exact match first (no padding)
        let verified_content = if actual_hash == *content_hash {
            full_content
        } else {
            // The last chunk wrote fewer bytes; the rest is pre-alloc zeros.
            // Find correct size by trying progressive trim (at most one chunk worth).
            let trim_start = full_content.len().saturating_sub(manifest.chunk_size);
            let mut found = None;
            for trim_len in 0..=manifest.chunk_size {
                let trimmed = &full_content[..full_content.len() - trim_len];
                let h = format!("sha256:{}", hex::encode(Sha256::digest(trimmed)));
                if h == *content_hash {
                    found = Some(trimmed.to_vec());
                    break;
                }
                if trim_start + trim_len >= full_content.len() {
                    break;
                }
            }
            found.ok_or_else(|| anyhow!("Content hash mismatch after download"))?
        };

        // Atomically rename temp to final
        tokio::fs::rename(&tmp_path, output_path).await?;

        // Clean up progress tracking
        state.chunk_progress.remove(path);

        Ok(verified_content)
    }

    /// Download and decrypt a file from the server (single-request, non-resumable)
    #[allow(dead_code)]
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

        let expected_hash = response
            .headers()
            .get("X-Content-Hash")
            .and_then(|v| v.to_str().ok())
            .map(String::from);

        let body = response.bytes().await?;

        let transmission = encryption::TransmissionFile::from_cbor(&body)
            .context("Failed to parse transmission file")?;

        // Verify signature over the body CBOR
        let body_cbor = transmission.body().to_cbor();
        let valid = encryption::verify(
            &self.server_verify_key,
            &body_cbor,
            transmission.signature(),
            transmission.timestamp(),
        )?;
        if !valid {
            return Err(anyhow!("Invalid file signature"));
        }

        let chunked = match transmission.into_body() {
            encryption::Content::ChunkedEncrypted(c) => c,
            _ => return Err(anyhow!("Expected chunked encrypted content")),
        };

        let decrypted = encryption::decrypt(&self.x25519_identity, &chunked)?;
        let plain_bytes = decrypted.into_inner();

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
            if !subscribed_groups.contains(&file.group) {
                return false;
            }

            match state.file_metadata.get(&file.path) {
                Some(existing) => {
                    existing.modified_at != file.modified_at
                        || existing.content_hash != file.content_hash
                }
                None => match state.file_hashes.get(&file.path) {
                    Some(existing_hash) => existing_hash != &file.content_hash,
                    None => true,
                },
            }
        })
        .cloned()
        .collect()
}

/// Determine the output path for a file
pub fn get_output_path(file: &ManifestFileEntry, config: &ClientConfig) -> Option<PathBuf> {
    let subscription = config.subscriptions.get(&file.group)?;

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
        let parent = std::path::Path::new(&file.path).parent();
        match parent {
            Some(p) if !p.as_os_str().is_empty() => {
                subscription.output_directory.join(p).join(&final_name)
            }
            _ => subscription.output_directory.join(&final_name),
        }
    } else {
        subscription.output_directory.join(&final_name)
    };

    Some(path)
}
