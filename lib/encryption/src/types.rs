use serde::{Deserialize, Serialize};

pub const CURRENT_VERSION: u64 = 2;

/// File content wrapper for transmission
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type")]
pub enum Content {
    /// Age-encrypted content
    Encrypted(Vec<u8>),
    /// Unencrypted content
    Plain(Vec<u8>),
}

impl Content {
    pub fn len(&self) -> usize {
        match self {
            Content::Encrypted(items) | Content::Plain(items) => items.len(),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn to_cbor(&self) -> Vec<u8> {
        minicbor_serde::to_vec(&self).unwrap()
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self, Content::Encrypted(_))
    }

    pub fn plain(self) -> Option<Vec<u8>> {
        match self {
            Self::Encrypted(_) => None,
            Self::Plain(v) => Some(v),
        }
    }

    pub fn encrypted(self) -> Option<Vec<u8>> {
        match self {
            Self::Encrypted(v) => Some(v),
            Self::Plain(_) => None,
        }
    }

    pub fn into_inner(self) -> Vec<u8> {
        match self {
            Self::Encrypted(v) | Self::Plain(v) => v,
        }
    }
}

impl std::fmt::Display for Content {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}(length: {})",
            if self.is_encrypted() {
                "Encrypted"
            } else {
                "Plain"
            },
            self.len()
        )
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

/// Age encryption identity (private key for decryption)
#[derive(Clone)]
pub struct AgeIdentity {
    inner: age::x25519::Identity,
}

impl AgeIdentity {
    pub fn generate() -> Self {
        Self {
            inner: age::x25519::Identity::generate(),
        }
    }

    /// Parse from age identity string (AGE-SECRET-KEY-1...)
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        let inner: age::x25519::Identity = s
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid age identity string"))?;
        Ok(Self { inner })
    }

    /// Convert to age identity string
    pub fn to_string(&self) -> String {
        use age::secrecy::ExposeSecret;
        self.inner.to_string().expose_secret().to_string()
    }

    /// Get the public recipient for this identity
    pub fn to_recipient(&self) -> AgeRecipient {
        AgeRecipient {
            inner: self.inner.to_public(),
        }
    }

    pub(crate) fn inner(&self) -> &age::x25519::Identity {
        &self.inner
    }
}

impl std::fmt::Debug for AgeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgeIdentity")
            .field("recipient", &self.to_recipient())
            .finish_non_exhaustive()
    }
}

/// Age recipient (public key for encryption)
#[derive(Clone)]
pub struct AgeRecipient {
    inner: age::x25519::Recipient,
}

impl AgeRecipient {
    /// Parse from age recipient string (age1...)
    pub fn from_str(s: &str) -> anyhow::Result<Self> {
        let inner: age::x25519::Recipient = s
            .parse()
            .map_err(|_| anyhow::anyhow!("Invalid age recipient string"))?;
        Ok(Self { inner })
    }

    /// Convert to age recipient string
    pub fn to_string(&self) -> String {
        self.inner.to_string()
    }

    pub(crate) fn inner(&self) -> &age::x25519::Recipient {
        &self.inner
    }
}

impl std::fmt::Debug for AgeRecipient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AgeRecipient")
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
    /// Age identity (for decryption)
    pub age_identity: Option<AgeIdentity>,
    /// Age recipient (for encryption)
    pub age_recipient: AgeRecipient,
}

impl KeyStore {
    /// Create a new KeyStore with all keys
    pub fn new(signing_key: SigningKey, age_identity: AgeIdentity) -> Self {
        let verifying_key = signing_key.verifying_key();
        let age_recipient = age_identity.to_recipient();
        Self {
            signing_key: Some(signing_key),
            verifying_key,
            age_identity: Some(age_identity),
            age_recipient,
        }
    }

    /// Create a public-only KeyStore (for storing other party's public keys)
    pub fn public_only(verifying_key: VerifyingKey, age_recipient: AgeRecipient) -> Self {
        Self {
            signing_key: None,
            verifying_key,
            age_identity: None,
            age_recipient,
        }
    }

    /// Remove private keys, keeping only public keys
    pub fn into_public_only(self) -> Self {
        Self {
            signing_key: None,
            verifying_key: self.verifying_key,
            age_identity: None,
            age_recipient: self.age_recipient,
        }
    }

    /// Check if this KeyStore has private keys
    pub fn has_private_keys(&self) -> bool {
        self.signing_key.is_some() && self.age_identity.is_some()
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
    /// Age identity string (private, optional)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub age_identity: Option<String>,
    /// Age recipient string (public)
    pub age_recipient: String,
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
            age_identity: ks.age_identity.as_ref().map(|i| i.to_string()),
            age_recipient: ks.age_recipient.to_string(),
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

        let age_recipient = AgeRecipient::from_str(&self.age_recipient)?;

        let age_identity = if let Some(ref id) = self.age_identity {
            Some(AgeIdentity::from_str(id)?)
        } else {
            None
        };

        Ok(KeyStore {
            signing_key,
            verifying_key,
            age_identity,
            age_recipient,
        })
    }
}
