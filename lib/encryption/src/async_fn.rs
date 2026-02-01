use std::{fmt::Debug, path::Path};

use tokio::{
    fs::{File, OpenOptions},
    io::{AsyncReadExt as _, AsyncWriteExt as _},
};

use crate::types::{KeyStore, RawKeyStore};

pub async fn open_file_and_read<P: AsRef<Path>>(path: P) -> std::io::Result<Vec<u8>> {
    let mut file = File::open(path).await?;
    let mut buff = vec![];
    file.read_to_end(&mut buff).await?;
    Ok(buff)
}

pub async fn write_to_file<P: AsRef<Path>>(path: P, content: &[u8]) -> std::io::Result<()> {
    let mut file = OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(path)
        .await?;
    file.write_all(content).await?;
    Ok(())
}

pub async fn load_key<P: AsRef<Path>>(path: P) -> anyhow::Result<RawKeyStore> {
    let f = open_file_and_read(path).await?;
    Ok(serde_json::from_slice(&f)?)
}

pub async fn write_key<P: AsRef<Path> + Debug>(
    path: P,
    key_override: bool,
    key: &KeyStore,
) -> std::io::Result<()> {
    if path.as_ref().exists() && !key_override {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            format!("File exists in {path:?}"),
        ));
    }

    let raw = RawKeyStore::from_key_store(key);
    write_to_file(path, serde_json::to_string_pretty(&raw).unwrap().as_bytes()).await?;
    Ok(())
}

/// Load age identity from file (AGE-SECRET-KEY-1... format)
pub async fn load_age_identity<P: AsRef<Path>>(path: P) -> anyhow::Result<crate::AgeIdentity> {
    let content = open_file_and_read(path).await?;
    let s = String::from_utf8(content)?;
    // Parse the identity, skipping comment lines
    for line in s.lines() {
        let line = line.trim();
        if line.starts_with("AGE-SECRET-KEY-") {
            return crate::AgeIdentity::from_str(line);
        }
    }
    Err(anyhow::anyhow!("No age identity found in file"))
}

/// Write age identity to file in standard format
pub async fn write_age_identity<P: AsRef<Path>>(
    path: P,
    identity: &crate::AgeIdentity,
) -> std::io::Result<()> {
    let recipient = identity.to_recipient();
    let content = format!(
        "# created: {}\n# public key: {}\n{}\n",
        chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
        recipient.to_string(),
        identity.to_string()
    );
    write_to_file(path, content.as_bytes()).await
}

/// Load Ed25519 signing key from JSON file
pub async fn load_signing_key<P: AsRef<Path>>(path: P) -> anyhow::Result<crate::SigningKey> {
    let content = open_file_and_read(path).await?;
    let raw: crate::RawSigningKey = serde_json::from_slice(&content)?;
    raw.to_signing_key()
}

/// Write Ed25519 signing key to JSON file
pub async fn write_signing_key<P: AsRef<Path>>(
    path: P,
    key: &crate::SigningKey,
) -> std::io::Result<()> {
    let raw = crate::RawSigningKey::from_signing_key(key);
    write_to_file(path, serde_json::to_string_pretty(&raw).unwrap().as_bytes()).await
}

/// Load Ed25519 verifying key from JSON file
pub async fn load_verifying_key<P: AsRef<Path>>(path: P) -> anyhow::Result<crate::VerifyingKey> {
    let content = open_file_and_read(path).await?;
    let raw: crate::RawVerifyingKey = serde_json::from_slice(&content)?;
    raw.to_verifying_key()
}

/// Write Ed25519 verifying key (public only) to JSON file
pub async fn write_verifying_key<P: AsRef<Path>>(
    path: P,
    key: &crate::VerifyingKey,
) -> std::io::Result<()> {
    let raw = crate::RawVerifyingKey::from_verifying_key(key);
    write_to_file(path, serde_json::to_string_pretty(&raw).unwrap().as_bytes()).await
}
