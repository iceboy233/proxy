use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use hkdf::Hkdf;
use md5::{Digest, Md5};
use ring::{
    aead::{
        Aad, Algorithm, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, Tag, UnboundKey,
        AES_128_GCM, AES_256_GCM, CHACHA20_POLY1305, NONCE_LEN,
    },
    error::Unspecified,
};
use serde::Deserialize;
use sha1::Sha1;

pub const MAX_KEY_LEN: usize = 32;
pub const MAX_SALT_LEN: usize = MAX_KEY_LEN;

#[derive(Clone, Copy, Debug, Deserialize)]
pub enum Method {
    #[serde(rename = "aes-128-gcm")]
    Aes128Gcm,

    #[serde(rename = "aes-256-gcm")]
    Aes256Gcm,

    #[serde(rename = "chacha20-ietf-poly1305")]
    Chacha20IetfPoly1305,

    #[serde(rename = "2022-blake3-aes-128-gcm")]
    Blake3Aes128Gcm2022,

    #[serde(rename = "2022-blake3-aes-256-gcm")]
    Blake3Aes256Gcm2022,

    #[serde(rename = "2022-blake3-chacha20-poly1305")]
    Blake3Chacha20Poly1305_2022,
}

impl Method {
    pub fn algorithm(&self) -> &'static Algorithm {
        match self {
            Method::Aes128Gcm => &AES_128_GCM,
            Method::Aes256Gcm => &AES_256_GCM,
            Method::Chacha20IetfPoly1305 => &CHACHA20_POLY1305,
            Method::Blake3Aes128Gcm2022 => &AES_128_GCM,
            Method::Blake3Aes256Gcm2022 => &AES_256_GCM,
            Method::Blake3Chacha20Poly1305_2022 => &CHACHA20_POLY1305,
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
        if self.is_spec_2022() {
            65535
        } else {
            16383
        }
    }

    pub fn is_spec_2022(&self) -> bool {
        match self {
            Method::Aes128Gcm => false,
            Method::Aes256Gcm => false,
            Method::Chacha20IetfPoly1305 => false,
            Method::Blake3Aes128Gcm2022 => true,
            Method::Blake3Aes256Gcm2022 => true,
            Method::Blake3Chacha20Poly1305_2022 => true,
        }
    }
}

#[derive(Clone, Copy)]
pub struct MasterKey([u8; MAX_KEY_LEN]);

impl MasterKey {
    pub fn new(method: Method, password: &str) -> Option<Self> {
        let mut key = [0u8; MAX_KEY_LEN];
        if method.is_spec_2022() {
            let decoded_len = base64::engine::general_purpose::STANDARD_NO_PAD
                .decode_slice(password, &mut key)
                .ok()?;
            if decoded_len != method.key_len() {
                return None;
            }
        } else {
            let mut md5 = Md5::new();
            md5.update(password);
            key[..16].copy_from_slice(md5.finalize_reset().as_slice());
            if method.key_len() > 16 {
                md5.update(&key[..16]);
                md5.update(password);
                key[16..].copy_from_slice(md5.finalize().as_slice());
            }
        }
        Some(Self(key))
    }

    fn derive(&self, method: Method, salt: &[u8]) -> UnboundKey {
        debug_assert_eq!(salt.len(), method.salt_len());

        let key = &self.0[..method.key_len()];
        let mut derived_key = [0u8; MAX_KEY_LEN];
        if method.is_spec_2022() {
            let hash = blake3::Hasher::new_derive_key("shadowsocks 2022 session subkey")
                .update(key)
                .update(salt)
                .finalize();
            derived_key.copy_from_slice(hash.as_slice());
        } else {
            Hkdf::<Sha1>::new(Some(salt), key)
                .expand(b"ss-subkey", &mut derived_key)
                .unwrap();
        }
        UnboundKey::new(method.algorithm(), &derived_key[..method.key_len()]).unwrap()
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

    pub fn decrypt(&mut self, in_out: &mut [u8]) -> bool {
        self.0.open_in_place(Aad::empty(), in_out).is_ok()
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
