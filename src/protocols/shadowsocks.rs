use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use ring::{
    aead::{
        Aad, Algorithm, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, Tag, UnboundKey,
        AES_128_GCM, NONCE_LEN,
    },
    error::Unspecified,
};
use serde::Deserialize;

pub const MAX_KEY_LEN: usize = 32;
pub const MAX_SALT_LEN: usize = MAX_KEY_LEN;

#[derive(Clone, Copy, Debug, Deserialize)]
pub enum Method {
    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Blake3Aes128Gcm2022,
}

impl Method {
    // TODO: support no encryption and non-aead
    pub fn algorithm(&self) -> &'static Algorithm {
        match self {
            Method::Blake3Aes128Gcm2022 => &AES_128_GCM,
        }
    }

    pub fn key_len(&self) -> usize {
        self.algorithm().key_len()
    }

    pub fn salt_len(&self) -> usize {
        self.key_len()
    }

    pub fn nonce_len(&self) -> usize {
        self.algorithm().nonce_len()
    }

    pub fn tag_len(&self) -> usize {
        self.algorithm().tag_len()
    }

    pub fn max_chunk_size(&self) -> usize {
        65535
    }
}

#[derive(Clone, Copy)]
pub struct MasterKey([u8; MAX_KEY_LEN]);

impl MasterKey {
    pub fn new(method: Method, password: &str) -> Option<Self> {
        let mut key: [u8; 32] = [0u8; MAX_KEY_LEN];

        // TODO: support legacy methods
        let decoded_len = base64::engine::general_purpose::STANDARD_NO_PAD
            .decode_slice(password, &mut key)
            .ok()?;
        if decoded_len != method.key_len() {
            return None;
        }

        Some(Self(key))
    }

    fn derive(&self, method: Method, salt: &[u8]) -> UnboundKey {
        assert_eq!(salt.len(), method.salt_len());

        // TODO: support legacy methods
        let mut hasher = blake3::Hasher::new_derive_key("shadowsocks 2022 session subkey");
        hasher.update(&self.0[..method.key_len()]);
        hasher.update(salt);
        let hash = hasher.finalize();
        let derived_key = &hash.as_bytes()[..method.key_len()];
        let algorithm = method.algorithm();
        UnboundKey::new(algorithm, derived_key).unwrap()
    }
}

pub struct EncryptionKey(SealingKey<NonceCounter>);

impl EncryptionKey {
    pub fn new(method: Method, master_key: &MasterKey, salt: &[u8]) -> Self {
        let derived_key = master_key.derive(method, salt);
        let nonce_counter = NonceCounter::new();
        Self(SealingKey::new(derived_key, nonce_counter))
    }

    pub fn encrypt(&mut self, in_out: &mut [u8]) -> Tag {
        self.0
            .seal_in_place_separate_tag(Aad::empty(), in_out)
            .unwrap()
    }
}

pub struct DecryptionKey(OpeningKey<NonceCounter>);

impl DecryptionKey {
    pub fn new(method: Method, master_key: &MasterKey, salt: &[u8]) -> Self {
        let derived_key = master_key.derive(method, salt);
        let nonce_counter = NonceCounter::new();
        Self(OpeningKey::new(derived_key, nonce_counter))
    }

    pub fn decrypt<'a>(&mut self, in_out: &'a mut [u8]) -> Option<&'a mut [u8]> {
        self.0.open_in_place(Aad::empty(), in_out).ok()
    }
}

struct NonceCounter(u128);

impl NonceCounter {
    fn new() -> Self {
        Self(0)
    }
}

impl NonceSequence for NonceCounter {
    fn advance(&mut self) -> Result<Nonce, Unspecified> {
        let mut bytes = [0u8; NONCE_LEN];
        bytes.copy_from_slice(&self.0.to_le_bytes()[..NONCE_LEN]);
        self.0 = self.0.wrapping_add(1);
        let nonce = Nonce::assume_unique_for_key(bytes);
        Ok(nonce)
    }
}

pub fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
