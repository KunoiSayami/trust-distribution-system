use std::io::{Read, Write};

use crate::types::{AgeIdentity, AgeRecipient, KeyStore, SigningKey, VerifyingKey};
use crate::Content;
use anyhow::anyhow;
use ed25519_dalek::Signer;
use sha2::{Digest, Sha256};

/// Generate a new keypair (both signing and encryption keys)
pub fn generate_keypair() -> KeyStore {
    let signing_key = SigningKey::generate();
    let age_identity = AgeIdentity::generate();
    KeyStore::new(signing_key, age_identity)
}

/// Sign content with Ed25519 key
/// Returns (signature, timestamp)
pub fn sign(key: &SigningKey, content: &[u8]) -> anyhow::Result<(Vec<u8>, i64)> {
    let now = chrono::Utc::now();
    let timestamp = now.timestamp_millis();

    // Create digest of content + timestamp
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

    // Recreate the digest
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

/// Encrypt content using age for a specific recipient
pub fn encrypt(recipient: &AgeRecipient, plain: Vec<u8>) -> anyhow::Result<Content> {
    let recipient_clone = recipient.inner().clone();
    let recipients: Vec<&dyn age::Recipient> = vec![&recipient_clone];
    let encryptor = age::Encryptor::with_recipients(recipients.into_iter())
        .map_err(|_| anyhow!("Failed to create encryptor"))?;

    let mut encrypted = vec![];
    let mut writer = encryptor.wrap_output(&mut encrypted)?;
    writer.write_all(&plain)?;
    writer.finish()?;

    Ok(Content::Encrypted(encrypted))
}

/// Encrypt using KeyStore's age recipient (convenience function)
pub fn encrypt_with_keystore(key: &KeyStore, plain: Vec<u8>) -> anyhow::Result<Content> {
    encrypt(&key.age_recipient, plain)
}

/// Decrypt age-encrypted content
pub fn decrypt(identity: &AgeIdentity, encrypted: Vec<u8>) -> anyhow::Result<Content> {
    let decryptor = age::Decryptor::new(&encrypted[..])?;

    let mut decrypted = vec![];
    let mut reader = decryptor.decrypt(std::iter::once(identity.inner() as &dyn age::Identity))?;
    reader.read_to_end(&mut decrypted)?;

    Ok(Content::Plain(decrypted))
}

/// Decrypt using KeyStore's age identity (convenience function)
pub fn decrypt_with_keystore(key: &KeyStore, encrypted: Vec<u8>) -> anyhow::Result<Content> {
    let identity = key
        .age_identity
        .as_ref()
        .ok_or_else(|| anyhow!("No age identity available"))?;
    decrypt(identity, encrypted)
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

        // Wrong content should fail
        assert!(!verify(&ks.verifying_key, b"wrong", &signature, timestamp).unwrap());

        // Wrong timestamp should fail
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

        let encrypted = encrypt(&ks.age_recipient, CONTENT.to_vec()).unwrap();
        assert!(encrypted.is_encrypted());

        let decrypted = decrypt(ks.age_identity.as_ref().unwrap(), encrypted.into_inner()).unwrap();
        assert_eq!(decrypted.plain().unwrap(), CONTENT);
    }

    #[test]
    fn test_encrypt_decrypt_with_keystore() {
        let ks = generate_keypair();

        let encrypted = encrypt_with_keystore(&ks, CONTENT.to_vec()).unwrap();
        assert!(encrypted.is_encrypted());

        let decrypted = decrypt_with_keystore(&ks, encrypted.into_inner()).unwrap();
        assert_eq!(decrypted.plain().unwrap(), CONTENT);
    }

    #[test]
    fn test_cross_party_encryption() {
        // Simulate server encrypting for client
        let server_ks = generate_keypair();
        let client_ks = generate_keypair();

        // Server encrypts using client's public key (recipient)
        let encrypted = encrypt(&client_ks.age_recipient, CONTENT.to_vec()).unwrap();

        // Client decrypts using their private key (identity)
        let decrypted =
            decrypt(client_ks.age_identity.as_ref().unwrap(), encrypted.into_inner()).unwrap();
        assert_eq!(decrypted.plain().unwrap(), CONTENT);

        // Server cannot decrypt (doesn't have client's identity)
        let encrypted2 = encrypt(&client_ks.age_recipient, CONTENT.to_vec()).unwrap();
        let result = decrypt(
            server_ks.age_identity.as_ref().unwrap(),
            encrypted2.into_inner(),
        );
        assert!(result.is_err());
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

        // Can still verify signatures
        let (signature, timestamp) = sign_with_keystore(&ks, CONTENT).unwrap();
        assert!(verify_with_keystore(&public_ks, CONTENT, &signature, timestamp).unwrap());

        // Can still encrypt to this recipient
        let encrypted = encrypt_with_keystore(&public_ks, CONTENT.to_vec()).unwrap();
        assert!(encrypted.is_encrypted());

        // But public-only cannot sign or decrypt
        assert!(sign_with_keystore(&public_ks, CONTENT).is_err());
        assert!(decrypt_with_keystore(&public_ks, encrypted.into_inner()).is_err());
    }
}
