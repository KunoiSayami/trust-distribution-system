use crate::Content;
use crate::types::{
    CHUNK_SIZE, ChunkedEncrypted, KeyStore, SigningKey, VerifyingKey, X25519Identity,
    X25519Recipient,
};
use aes_gcm::{
    Aes256Gcm, Key, Nonce,
    aead::{Aead, AeadCore, KeyInit, Payload},
};
use anyhow::anyhow;
use ed25519_dalek::Signer;
use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

/// Generate a new keypair (both signing and encryption keys)
pub fn generate_keypair() -> KeyStore {
    let signing_key = SigningKey::generate();
    let x25519_identity = X25519Identity::generate();
    KeyStore::new(signing_key, x25519_identity)
}

/// Sign content with Ed25519 key
/// Returns (signature, timestamp)
pub fn sign(key: &SigningKey, content: &[u8]) -> anyhow::Result<(Vec<u8>, i64)> {
    let now = chrono::Utc::now();
    let timestamp = now.timestamp_millis();

    let digest = {
        let mut hasher = Sha256::new();
        hasher.update(content);
        hasher.update(&timestamp.to_be_bytes());
        hasher.finalize()
    };

    let signature = key.inner().sign(&digest);
    Ok((signature.to_bytes().to_vec(), timestamp))
}

/// Sign content using KeyStore (convenience function)
pub fn sign_with_keystore(key: &KeyStore, content: &[u8]) -> anyhow::Result<(Vec<u8>, i64)> {
    let signing_key = key
        .signing_key
        .as_ref()
        .ok_or_else(|| anyhow!("No signing key available"))?;
    sign(signing_key, content)
}

/// Verify Ed25519 signature
pub fn verify(
    key: &VerifyingKey,
    content: &[u8],
    signature_raw: &[u8],
    timestamp: i64,
) -> anyhow::Result<bool> {
    use ed25519_dalek::Verifier;

    let signature_bytes: [u8; 64] = signature_raw
        .try_into()
        .map_err(|_| anyhow!("Invalid signature length"))?;
    let signature = ed25519_dalek::Signature::from_bytes(&signature_bytes);

    let digest = {
        let mut hasher = Sha256::new();
        hasher.update(content);
        hasher.update(&timestamp.to_be_bytes());
        hasher.finalize()
    };

    Ok(key.inner().verify(&digest, &signature).is_ok())
}

/// Verify signature using KeyStore (convenience function)
pub fn verify_with_keystore(
    key: &KeyStore,
    content: &[u8],
    signature_raw: &[u8],
    timestamp: i64,
) -> anyhow::Result<bool> {
    verify(&key.verifying_key, content, signature_raw, timestamp)
}

/// Derive per-chunk nonce: XOR last 8 bytes of file_nonce with chunk_index (little-endian)
fn chunk_nonce(file_nonce: &[u8; 12], chunk_index: u64) -> [u8; 12] {
    let mut nonce = *file_nonce;
    let idx = chunk_index.to_le_bytes();
    for i in 0..8 {
        nonce[4 + i] ^= idx[i];
    }
    nonce
}

/// Derive the AES-256 file key from the X25519 shared secret via HKDF-SHA256
fn derive_file_key(
    identity: &X25519Identity,
    ephemeral_public_bytes: &[u8],
    file_nonce: &[u8],
) -> anyhow::Result<[u8; 32]> {
    let epk_bytes: [u8; 32] = ephemeral_public_bytes
        .try_into()
        .map_err(|_| anyhow!("Ephemeral public key must be 32 bytes"))?;
    let ephemeral_public = x25519_dalek::PublicKey::from(epk_bytes);
    let shared = identity.secret().diffie_hellman(&ephemeral_public);

    let hkdf = Hkdf::<Sha256>::new(Some(file_nonce), shared.as_bytes());
    let mut file_key = [0u8; 32];
    hkdf.expand(b"tds-aes-gcm-v1", &mut file_key)
        .map_err(|_| anyhow!("HKDF expand failed"))?;
    Ok(file_key)
}

/// Encrypt plaintext into chunked AES-256-GCM format
pub fn encrypt(recipient: &X25519Recipient, plain: Vec<u8>) -> anyhow::Result<Content> {
    use rand::rngs::OsRng;
    use x25519_dalek::EphemeralSecret;

    let ephemeral_secret = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = x25519_dalek::PublicKey::from(&ephemeral_secret);
    let shared = ephemeral_secret.diffie_hellman(recipient.public_key());

    let file_nonce_arr = Aes256Gcm::generate_nonce(OsRng);
    let file_nonce: [u8; 12] = file_nonce_arr.into();

    let hkdf = Hkdf::<Sha256>::new(Some(&file_nonce), shared.as_bytes());
    let mut file_key = [0u8; 32];
    hkdf.expand(b"tds-aes-gcm-v1", &mut file_key)
        .map_err(|_| anyhow!("HKDF expand failed"))?;

    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&file_key));

    let mut chunks = Vec::new();
    for (i, chunk) in plain.chunks(CHUNK_SIZE).enumerate() {
        let nonce_arr = chunk_nonce(&file_nonce, i as u64);
        let nonce = Nonce::from_slice(&nonce_arr);
        let aad = (i as u64).to_be_bytes();
        let ciphertext = cipher
            .encrypt(
                nonce,
                Payload {
                    msg: chunk,
                    aad: &aad,
                },
            )
            .map_err(|_| anyhow!("AES-GCM encryption failed for chunk {i}"))?;
        chunks.push(ciphertext);
    }

    let chunk_count = chunks.len() as u64;
    file_key.zeroize();

    Ok(Content::ChunkedEncrypted(ChunkedEncrypted {
        ephemeral_public_key: ephemeral_public.as_bytes().to_vec(),
        file_nonce: file_nonce.to_vec(),
        chunk_count,
        chunks,
    }))
}

/// Encrypt using KeyStore's X25519 recipient (convenience function)
pub fn encrypt_with_keystore(key: &KeyStore, plain: Vec<u8>) -> anyhow::Result<Content> {
    encrypt(&key.x25519_recipient, plain)
}

/// Decrypt all chunks from a ChunkedEncrypted payload
pub fn decrypt(identity: &X25519Identity, payload: &ChunkedEncrypted) -> anyhow::Result<Content> {
    let file_nonce_arr: [u8; 12] = payload
        .file_nonce
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("file_nonce must be 12 bytes"))?;

    let mut file_key =
        derive_file_key(identity, &payload.ephemeral_public_key, &payload.file_nonce)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&file_key));

    let mut plaintext = Vec::new();
    for (i, ciphertext) in payload.chunks.iter().enumerate() {
        let nonce_arr = chunk_nonce(&file_nonce_arr, i as u64);
        let nonce = Nonce::from_slice(&nonce_arr);
        let aad = (i as u64).to_be_bytes();
        let chunk = cipher
            .decrypt(
                nonce,
                Payload {
                    msg: ciphertext.as_slice(),
                    aad: &aad,
                },
            )
            .map_err(|_| {
                anyhow!("AES-GCM decryption failed for chunk {i}: authentication error")
            })?;
        plaintext.extend_from_slice(&chunk);
    }

    file_key.zeroize();
    Ok(Content::Plain(plaintext))
}

/// Decrypt a single chunk by index — enables resumable downloads
pub fn decrypt_chunk(
    identity: &X25519Identity,
    payload: &ChunkedEncrypted,
    chunk_index: usize,
) -> anyhow::Result<Vec<u8>> {
    let file_nonce_arr: [u8; 12] = payload
        .file_nonce
        .as_slice()
        .try_into()
        .map_err(|_| anyhow!("file_nonce must be 12 bytes"))?;

    let ciphertext = payload.chunks.get(chunk_index).ok_or_else(|| {
        anyhow!(
            "Chunk index {chunk_index} out of range (count: {})",
            payload.chunk_count
        )
    })?;

    let mut file_key =
        derive_file_key(identity, &payload.ephemeral_public_key, &payload.file_nonce)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&file_key));

    let nonce_arr = chunk_nonce(&file_nonce_arr, chunk_index as u64);
    let nonce = Nonce::from_slice(&nonce_arr);
    let aad = (chunk_index as u64).to_be_bytes();
    let chunk = cipher
        .decrypt(
            nonce,
            Payload {
                msg: ciphertext.as_slice(),
                aad: &aad,
            },
        )
        .map_err(|_| {
            anyhow!("AES-GCM decryption failed for chunk {chunk_index}: authentication error")
        })?;

    file_key.zeroize();
    Ok(chunk)
}

/// Decrypt using KeyStore's X25519 identity (convenience function)
pub fn decrypt_with_keystore(
    key: &KeyStore,
    payload: &ChunkedEncrypted,
) -> anyhow::Result<Content> {
    let identity = key
        .x25519_identity
        .as_ref()
        .ok_or_else(|| anyhow!("No X25519 identity available"))?;
    decrypt(identity, payload)
}

/// Compute SHA-256 hash of content
pub fn hash_content(content: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content);
    let result = hasher.finalize();
    format!("sha256:{}", hex::encode(result))
}

/// Verify SHA-256 hash
pub fn verify_hash(content: &[u8], expected_hash: &str) -> bool {
    let computed = hash_content(content);
    computed == expected_hash
}

#[cfg(test)]
mod test {
    use super::*;

    const CONTENT: &[u8] = b"Hello, World!";

    #[test]
    fn test_generate_keypair() {
        let ks = generate_keypair();
        assert!(ks.has_private_keys());
    }

    #[test]
    fn test_sign_verify() {
        let ks = generate_keypair();
        let signing_key = ks.signing_key.as_ref().unwrap();

        let (signature, timestamp) = sign(signing_key, CONTENT).unwrap();

        assert!(verify(&ks.verifying_key, CONTENT, &signature, timestamp).unwrap());
        assert!(!verify(&ks.verifying_key, b"wrong", &signature, timestamp).unwrap());
        assert!(!verify(&ks.verifying_key, CONTENT, &signature, timestamp + 1).unwrap());
    }

    #[test]
    fn test_sign_verify_with_keystore() {
        let ks = generate_keypair();
        let (signature, timestamp) = sign_with_keystore(&ks, CONTENT).unwrap();
        assert!(verify_with_keystore(&ks, CONTENT, &signature, timestamp).unwrap());
    }

    #[test]
    fn test_encrypt_decrypt() {
        let ks = generate_keypair();

        let encrypted = encrypt(&ks.x25519_recipient, CONTENT.to_vec()).unwrap();
        assert!(encrypted.is_encrypted());

        let chunked = encrypted.chunked().unwrap();
        let decrypted = decrypt(ks.x25519_identity.as_ref().unwrap(), &chunked).unwrap();
        assert_eq!(decrypted.plain().unwrap(), CONTENT);
    }

    #[test]
    fn test_encrypt_decrypt_with_keystore() {
        let ks = generate_keypair();

        let encrypted = encrypt_with_keystore(&ks, CONTENT.to_vec()).unwrap();
        assert!(encrypted.is_encrypted());

        let chunked = encrypted.chunked().unwrap();
        let decrypted = decrypt_with_keystore(&ks, &chunked).unwrap();
        assert_eq!(decrypted.plain().unwrap(), CONTENT);
    }

    #[test]
    fn test_decrypt_chunk() {
        let ks = generate_keypair();

        let encrypted = encrypt(&ks.x25519_recipient, CONTENT.to_vec()).unwrap();
        let chunked = encrypted.chunked().unwrap();

        let chunk_bytes = decrypt_chunk(ks.x25519_identity.as_ref().unwrap(), &chunked, 0).unwrap();
        assert_eq!(chunk_bytes, CONTENT);
    }

    #[test]
    fn test_cross_party_encryption() {
        let client_ks = generate_keypair();

        let encrypted = encrypt(&client_ks.x25519_recipient, CONTENT.to_vec()).unwrap();
        let chunked = encrypted.chunked().unwrap();
        let decrypted = decrypt(client_ks.x25519_identity.as_ref().unwrap(), &chunked).unwrap();
        assert_eq!(decrypted.plain().unwrap(), CONTENT);

        // Wrong key cannot decrypt
        let other_ks = generate_keypair();
        let encrypted2 = encrypt(&client_ks.x25519_recipient, CONTENT.to_vec()).unwrap();
        let chunked2 = encrypted2.chunked().unwrap();
        let result = decrypt(other_ks.x25519_identity.as_ref().unwrap(), &chunked2);
        assert!(result.is_err());
    }

    #[test]
    fn test_multi_chunk() {
        let ks = generate_keypair();
        // Create content larger than one chunk
        let large_content: Vec<u8> = (0..CHUNK_SIZE + 100).map(|i| (i % 256) as u8).collect();

        let encrypted = encrypt(&ks.x25519_recipient, large_content.clone()).unwrap();
        let chunked = encrypted.chunked().unwrap();
        assert_eq!(chunked.chunk_count, 2);

        // Full decrypt
        let decrypted = decrypt(ks.x25519_identity.as_ref().unwrap(), &chunked).unwrap();
        assert_eq!(decrypted.plain().unwrap(), large_content);

        // Per-chunk decrypt
        let chunk0 = decrypt_chunk(ks.x25519_identity.as_ref().unwrap(), &chunked, 0).unwrap();
        let chunk1 = decrypt_chunk(ks.x25519_identity.as_ref().unwrap(), &chunked, 1).unwrap();
        let mut reassembled = chunk0;
        reassembled.extend_from_slice(&chunk1);
        assert_eq!(reassembled, large_content);
    }

    #[test]
    fn test_hash_content() {
        let hash = hash_content(CONTENT);
        assert!(hash.starts_with("sha256:"));
        assert!(verify_hash(CONTENT, &hash));
        assert!(!verify_hash(b"wrong", &hash));
    }

    #[test]
    fn test_public_only_keystore() {
        let ks = generate_keypair();
        let public_ks = ks.clone().into_public_only();

        assert!(!public_ks.has_private_keys());

        let (signature, timestamp) = sign_with_keystore(&ks, CONTENT).unwrap();
        assert!(verify_with_keystore(&public_ks, CONTENT, &signature, timestamp).unwrap());

        let encrypted = encrypt_with_keystore(&public_ks, CONTENT.to_vec()).unwrap();
        assert!(encrypted.is_encrypted());

        assert!(sign_with_keystore(&public_ks, CONTENT).is_err());
        let chunked = encrypted.chunked().unwrap();
        assert!(decrypt_with_keystore(&public_ks, &chunked).is_err());
    }
}
