use serde::{Deserialize, Serialize};

pub const CHUNK_SIZE: usize = 1_048_576; // 1 MB plaintext per chunk (ciphertext = CHUNK_SIZE + 16)
pub const CURRENT_VERSION: u64 = 3;

/// Chunked AES-256-GCM encrypted content
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct ChunkedEncrypted {
    /// Sender's ephemeral X25519 public key (32 bytes)
    pub ephemeral_public_key: Vec<u8>,
    /// Per-file random nonce (12 bytes)
    pub file_nonce: Vec<u8>,
    /// Total number of chunks
    pub chunk_count: u64,
    /// AES-256-GCM ciphertext per chunk (includes 16-byte GCM tag)
    pub chunks: Vec<Vec<u8>>,
}

/// File content wrapper for transmission
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Content {
    /// Legacy Age-encrypted content (kept for CBOR format compatibility)
    Encrypted(Vec<u8>),
    /// Unencrypted content
    Plain(Vec<u8>),
    /// AES-256-GCM chunked encrypted content
    ChunkedEncrypted(ChunkedEncrypted),
}

impl Content {
    pub fn len(&self) -> usize {
        match self {
            Content::Encrypted(items) | Content::Plain(items) => items.len(),
            Content::ChunkedEncrypted(c) => c.chunks.iter().map(|ch| ch.len()).sum(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        minicbor_serde::to_vec(&self).unwrap()
    }

    pub fn from_cbor(data: &[u8]) -> anyhow::Result<Self> {
        Ok(minicbor_serde::from_slice(data)?)
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self, Content::Encrypted(_) | Content::ChunkedEncrypted(_))
    }

    pub fn plain(self) -> Option<Vec<u8>> {
        match self {
            Self::Plain(v) => Some(v),
            _ => None,
        }
    }

    pub fn encrypted(self) -> Option<Vec<u8>> {
        match self {
            Self::Encrypted(v) => Some(v),
            _ => None,
        }
    }

    pub fn chunked(self) -> Option<ChunkedEncrypted> {
        match self {
            Self::ChunkedEncrypted(c) => Some(c),
            _ => None,
        }
    }

    pub fn into_inner(self) -> Vec<u8> {
        match self {
            Self::Encrypted(v) | Self::Plain(v) => v,
            Self::ChunkedEncrypted(_) => panic!("into_inner called on ChunkedEncrypted"),
        }
    }
}

impl std::fmt::Display for Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Encrypted(_) => write!(f, "Encrypted(length: {})", self.len()),
            Self::Plain(_) => write!(f, "Plain(length: {})", self.len()),
            Self::ChunkedEncrypted(c) => write!(
                f,
                "ChunkedEncrypted(chunks: {}, total: {})",
                c.chunk_count,
                self.len()
            ),
        }
    }
}

/// Wire transmission format for files
#[derive(Debug, Deserialize, Serialize)]
pub struct TransmissionFile {
    version: u64,
    timestamp: i64,
    body: Content,
    /// Ed25519 signature over (body_cbor || timestamp_bytes)
    signature: Vec<u8>,
}

impl TransmissionFile {
    pub fn new(timestamp: i64, body: Content, signature: Vec<u8>) -> Self {
        Self {
            version: CURRENT_VERSION,
            timestamp,
            body,
            signature,
        }
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        minicbor_serde::to_vec(&self).unwrap()
    }

    pub fn from_cbor(data: &[u8]) -> anyhow::Result<Self> {
        Ok(minicbor_serde::from_slice(data)?)
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn timestamp(&self) -> i64 {
        self.timestamp
    }

    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn body(&self) -> &Content {
        &self.body
    }

    pub fn into_body(self) -> Content {
        self.body
    }
}

impl std::fmt::Display for TransmissionFile {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "TransmissionFile v{}: timestamp={}, {}",
            self.version, self.timestamp, self.body
        )
    }
}

/// Ed25519 signing keypair
#[derive(Clone)]
pub struct SigningKey {
    inner: ed25519_dalek::SigningKey,
}

impl SigningKey {
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        Self {
            inner: ed25519_dalek::SigningKey::generate(&mut OsRng),
        }
    }

    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        Self {
            inner: ed25519_dalek::SigningKey::from_bytes(bytes),
        }
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey {
            inner: self.inner.verifying_key(),
        }
    }

    pub(crate) fn inner(&self) -> &ed25519_dalek::SigningKey {
        &self.inner
    }
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SigningKey")
            .field("public", &self.verifying_key())
            .finish_non_exhaustive()
    }
}

/// Ed25519 verifying (public) key
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifyingKey {
    inner: ed25519_dalek::VerifyingKey,
}

impl VerifyingKey {
    pub fn from_bytes(bytes: &[u8; 32]) -> anyhow::Result<Self> {
        Ok(Self {
            inner: ed25519_dalek::VerifyingKey::from_bytes(bytes)?,
        })
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }

    pub(crate) fn inner(&self) -> &ed25519_dalek::VerifyingKey {
        &self.inner
    }
}

/// Serializable key storage format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawSigningKey {
    /// Base64-encoded private key (32 bytes)
    pub private_key: String,
    /// Base64-encoded public key (32 bytes)
    pub public_key: String,
}

impl RawSigningKey {
    pub fn from_signing_key(key: &SigningKey) -> Self {
        use base64::{Engine, engine::general_purpose::STANDARD};
        Self {
            private_key: STANDARD.encode(key.to_bytes()),
            public_key: STANDARD.encode(key.verifying_key().to_bytes()),
        }
    }

    pub fn to_signing_key(&self) -> anyhow::Result<SigningKey> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let bytes = STANDARD.decode(&self.private_key)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid key length"))?;
        Ok(SigningKey::from_bytes(&bytes))
    }

    pub fn to_verifying_key(&self) -> anyhow::Result<VerifyingKey> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let bytes = STANDARD.decode(&self.public_key)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid key length"))?;
        VerifyingKey::from_bytes(&bytes)
    }
}

/// Serializable verifying key (public only)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawVerifyingKey {
    /// Base64-encoded public key (32 bytes)
    pub public_key: String,
}

impl RawVerifyingKey {
    pub fn from_verifying_key(key: &VerifyingKey) -> Self {
        use base64::{Engine, engine::general_purpose::STANDARD};
        Self {
            public_key: STANDARD.encode(key.to_bytes()),
        }
    }

    pub fn to_verifying_key(&self) -> anyhow::Result<VerifyingKey> {
        use base64::{Engine, engine::general_purpose::STANDARD};
        let bytes = STANDARD.decode(&self.public_key)?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid key length"))?;
        VerifyingKey::from_bytes(&bytes)
    }
}

/// X25519 private key for decryption (persistent, stored on disk)
#[derive(Clone)]
pub struct X25519Identity {
    secret: x25519_dalek::StaticSecret,
    public: x25519_dalek::PublicKey,
}

impl X25519Identity {
    pub fn generate() -> Self {
        use rand::rngs::OsRng;
        let secret = x25519_dalek::StaticSecret::random_from_rng(OsRng);
        let public = x25519_dalek::PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Parse from stored string: "X25519-SECRET-KEY-1:<lowercase hex of 32 bytes>"
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        let hex_part = s.strip_prefix("X25519-SECRET-KEY-1:").ok_or_else(|| {
            anyhow::anyhow!("Invalid X25519 identity string (expected X25519-SECRET-KEY-1: prefix)")
        })?;
        let bytes =
            hex::decode(hex_part).map_err(|_| anyhow::anyhow!("Invalid hex in X25519 identity"))?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("X25519 secret key must be 32 bytes"))?;
        let secret = x25519_dalek::StaticSecret::from(bytes);
        let public = x25519_dalek::PublicKey::from(&secret);
        Ok(Self { secret, public })
    }

    /// Serialize to stored string: "X25519-SECRET-KEY-1:<lowercase hex>"
    pub fn to_string(&self) -> String {
        format!(
            "X25519-SECRET-KEY-1:{}",
            hex::encode(self.secret.as_bytes())
        )
    }

    /// Get the public recipient for this identity
    pub fn to_recipient(&self) -> X25519Recipient {
        X25519Recipient(self.public)
    }

    pub(crate) fn secret(&self) -> &x25519_dalek::StaticSecret {
        &self.secret
    }
}

impl std::fmt::Debug for X25519Identity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519Identity")
            .field("recipient", &self.to_recipient())
            .finish_non_exhaustive()
    }
}

/// X25519 public key for encryption
#[derive(Clone)]
pub struct X25519Recipient(x25519_dalek::PublicKey);

impl X25519Recipient {
    /// Parse from stored string: "X25519-PUBLIC-KEY-1:<lowercase hex of 32 bytes>"
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        let hex_part = s.strip_prefix("X25519-PUBLIC-KEY-1:").ok_or_else(|| {
            anyhow::anyhow!(
                "Invalid X25519 recipient string (expected X25519-PUBLIC-KEY-1: prefix)"
            )
        })?;
        let bytes = hex::decode(hex_part)
            .map_err(|_| anyhow::anyhow!("Invalid hex in X25519 recipient"))?;
        let bytes: [u8; 32] = bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("X25519 public key must be 32 bytes"))?;
        Ok(Self(x25519_dalek::PublicKey::from(bytes)))
    }

    /// Serialize to stored string: "X25519-PUBLIC-KEY-1:<lowercase hex>"
    pub fn to_string(&self) -> String {
        format!("X25519-PUBLIC-KEY-1:{}", hex::encode(self.0.as_bytes()))
    }

    pub(crate) fn public_key(&self) -> &x25519_dalek::PublicKey {
        &self.0
    }
}

impl std::fmt::Debug for X25519Recipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("X25519Recipient")
            .field("key", &self.to_string())
            .finish()
    }
}

/// Combined key store for a party (server or client)
#[derive(Debug, Clone)]
pub struct KeyStore {
    /// Ed25519 signing key (for creating signatures)
    pub signing_key: Option<SigningKey>,
    /// Ed25519 verifying key (for verifying signatures)
    pub verifying_key: VerifyingKey,
    /// X25519 identity (for decryption)
    pub x25519_identity: Option<X25519Identity>,
    /// X25519 recipient (for encryption)
    pub x25519_recipient: X25519Recipient,
}

impl KeyStore {
    /// Create a new KeyStore with all keys
    pub fn new(signing_key: SigningKey, x25519_identity: X25519Identity) -> Self {
        let verifying_key = signing_key.verifying_key();
        let x25519_recipient = x25519_identity.to_recipient();
        Self {
            signing_key: Some(signing_key),
            verifying_key,
            x25519_identity: Some(x25519_identity),
            x25519_recipient,
        }
    }

    /// Create a public-only KeyStore (for storing other party's public keys)
    pub fn public_only(verifying_key: VerifyingKey, x25519_recipient: X25519Recipient) -> Self {
        Self {
            signing_key: None,
            verifying_key,
            x25519_identity: None,
            x25519_recipient,
        }
    }

    /// Remove private keys, keeping only public keys
    pub fn into_public_only(self) -> Self {
        Self {
            signing_key: None,
            verifying_key: self.verifying_key,
            x25519_identity: None,
            x25519_recipient: self.x25519_recipient,
        }
    }

    /// Check if this KeyStore has private keys
    pub fn has_private_keys(&self) -> bool {
        self.signing_key.is_some() && self.x25519_identity.is_some()
    }
}

/// Serializable key store format
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawKeyStore {
    /// Ed25519 signing key (private, optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_key: Option<String>,
    /// Ed25519 verifying key (public)
    pub verifying_key: String,
    /// X25519 identity string (private, optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x25519_identity: Option<String>,
    /// X25519 recipient string (public)
    pub x25519_recipient: String,
}

impl RawKeyStore {
    pub fn from_key_store(ks: &KeyStore) -> Self {
        use base64::{Engine, engine::general_purpose::STANDARD};
        Self {
            signing_key: ks
                .signing_key
                .as_ref()
                .map(|k| STANDARD.encode(k.to_bytes())),
            verifying_key: STANDARD.encode(ks.verifying_key.to_bytes()),
            x25519_identity: ks.x25519_identity.as_ref().map(|i| i.to_string()),
            x25519_recipient: ks.x25519_recipient.to_string(),
        }
    }

    pub fn to_key_store(&self) -> anyhow::Result<KeyStore> {
        use base64::{Engine, engine::general_purpose::STANDARD};

        let verifying_bytes = STANDARD.decode(&self.verifying_key)?;
        let verifying_bytes: [u8; 32] = verifying_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Invalid verifying key length"))?;
        let verifying_key = VerifyingKey::from_bytes(&verifying_bytes)?;

        let signing_key = if let Some(ref sk) = self.signing_key {
            let bytes = STANDARD.decode(sk)?;
            let bytes: [u8; 32] = bytes
                .try_into()
                .map_err(|_| anyhow::anyhow!("Invalid signing key length"))?;
            Some(SigningKey::from_bytes(&bytes))
        } else {
            None
        };

        let x25519_recipient = X25519Recipient::from_str(&self.x25519_recipient)?;

        let x25519_identity = if let Some(ref id) = self.x25519_identity {
            Some(X25519Identity::from_str(id)?)
        } else {
            None
        };

        Ok(KeyStore {
            signing_key,
            verifying_key,
            x25519_identity,
            x25519_recipient,
        })
    }
}
