use std::{
    io,
    pin::Pin,
    task::{Context, Poll},
    time::{SystemTime, UNIX_EPOCH},
};

use base64::Engine;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_util::{Sink, Stream};
use hkdf::Hkdf;
use log::warn;
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
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::codec::{Decoder, Encoder};

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

struct EncryptionKey(SealingKey<NonceCounter>);

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

struct DecryptionKey(OpeningKey<NonceCounter>);

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

pub struct Codec {
    kind: CodecKind,
    encode_header: bool,
    decode_state: DecodeState,
    method: Method,
    master_key: MasterKey,
    encryption_key: EncryptionKey,
    decryption_key: Option<DecryptionKey>,
    local_salt: [u8; MAX_SALT_LEN],
    remote_salt: [u8; MAX_SALT_LEN],
}

#[derive(Clone, Copy)]
pub enum CodecKind {
    Server,
    Client,
}

enum DecodeState {
    Init,
    Header,
    Length,
    Payload(usize),
    Discard,
}

impl Codec {
    pub fn new(kind: CodecKind, method: Method, master_key: MasterKey, salt: &[u8]) -> Self {
        let encryption_key = EncryptionKey::new(method, &master_key, salt);
        let mut local_salt = [0u8; MAX_SALT_LEN];
        local_salt[..method.salt_len()].copy_from_slice(&salt);
        Codec {
            kind,
            encode_header: method.is_spec_2022(),
            decode_state: DecodeState::Init,
            method,
            master_key,
            encryption_key,
            decryption_key: None,
            local_salt,
            remote_salt: [0u8; MAX_SALT_LEN],
        }
    }
}

impl Encoder<&[u8]> for Codec {
    type Error = io::Error;

    fn encode(&mut self, chunk: &[u8], dst: &mut BytesMut) -> Result<(), Self::Error> {
        debug_assert!(chunk.len() <= self.method.max_chunk_size());

        let offset = dst.len();
        if self.encode_header {
            match self.kind {
                CodecKind::Server => {
                    dst.put_u8(1);
                    dst.put_u64(timestamp());
                    dst.put_slice(&self.remote_salt[..self.method.salt_len()]);
                }
                CodecKind::Client => {
                    dst.put_u8(0);
                    dst.put_u64(timestamp());
                }
            }
            self.encode_header = false;
        }
        dst.put_u16(chunk.len() as u16);
        let tag = self.encryption_key.encrypt(&mut dst[offset..]);
        dst.put_slice(tag.as_ref());

        let offset = dst.len();
        dst.put_slice(&chunk);
        let tag = self.encryption_key.encrypt(&mut dst[offset..]);
        dst.put_slice(tag.as_ref());
        Ok(())
    }
}

impl Decoder for Codec {
    type Item = Bytes;
    type Error = io::Error;

    fn decode(&mut self, src: &mut BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        loop {
            match self.decode_state {
                DecodeState::Init => {
                    let salt_len = self.method.salt_len();
                    if src.len() < salt_len {
                        return Ok(None);
                    }
                    self.remote_salt[..salt_len].copy_from_slice(&src[..salt_len]);
                    self.decryption_key = Some(DecryptionKey::new(
                        self.method,
                        &self.master_key,
                        &src[..salt_len],
                    ));
                    src.advance(salt_len);
                    self.decode_state = DecodeState::Header;
                }
                DecodeState::Header => {
                    let salt_len = self.method.salt_len();
                    let tag_len = self.method.tag_len();
                    let read_len = match (self.kind, self.method.is_spec_2022()) {
                        (CodecKind::Server, true) => 1 + 8 + 2 + tag_len,
                        (CodecKind::Client, true) => 1 + 8 + salt_len + 2 + tag_len,
                        (_, false) => 2 + tag_len,
                    };
                    if src.len() < read_len {
                        return Ok(None);
                    }
                    if !self
                        .decryption_key
                        .as_mut()
                        .unwrap()
                        .decrypt(&mut src[..read_len])
                    {
                        self.decode_state = DecodeState::Discard;
                        continue;
                    };
                    if self.method.is_spec_2022() {
                        match self.kind {
                            CodecKind::Server => {
                                if src.get_u8() != 0 {
                                    self.decode_state = DecodeState::Discard;
                                    continue;
                                }
                                if src.get_u64().abs_diff(timestamp()) > 30 {
                                    warn!("time difference too large");
                                    self.decode_state = DecodeState::Discard;
                                    continue;
                                }
                            }
                            CodecKind::Client => {
                                if src.get_u8() != 1 {
                                    self.decode_state = DecodeState::Discard;
                                    continue;
                                }
                                if src.get_u64().abs_diff(timestamp()) > 30 {
                                    warn!("time difference too large");
                                    self.decode_state = DecodeState::Discard;
                                    continue;
                                }
                                if &src[..salt_len] != &self.local_salt[..salt_len] {
                                    warn!("salt mismatch");
                                    self.decode_state = DecodeState::Discard;
                                    continue;
                                }
                                src.advance(salt_len);
                            }
                        }
                    }
                    // TODO: test and insert remote salt
                    let payload_len = src.get_u16() as usize;
                    src.advance(tag_len);
                    self.decode_state = DecodeState::Payload(payload_len);
                }
                DecodeState::Length => {
                    let tag_len = self.method.tag_len();
                    if src.len() < 2 + tag_len {
                        return Ok(None);
                    }
                    if !self
                        .decryption_key
                        .as_mut()
                        .unwrap()
                        .decrypt(&mut src[..2 + tag_len])
                    {
                        self.decode_state = DecodeState::Discard;
                        continue;
                    };
                    let payload_len = src.get_u16() as usize;
                    src.advance(tag_len);
                    self.decode_state = DecodeState::Payload(payload_len);
                }
                DecodeState::Payload(len) => {
                    let tag_len = self.method.tag_len();
                    if src.len() < len + tag_len {
                        return Ok(None);
                    }
                    if !self
                        .decryption_key
                        .as_mut()
                        .unwrap()
                        .decrypt(&mut src[..len + tag_len])
                    {
                        self.decode_state = DecodeState::Discard;
                        continue;
                    };
                    let bytes = src.split_to(len).freeze();
                    src.advance(tag_len);
                    self.decode_state = DecodeState::Length;
                    return Ok(Some(bytes));
                }
                DecodeState::Discard => {
                    src.clear();
                    return Ok(None);
                }
            }
        }
    }
}

fn timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub struct ShadowsocksStream<T: Stream + for<'a> Sink<&'a [u8]>> {
    inner: T,
    max_chunk_size: usize,
    current_chunk: Option<Bytes>,
}

impl<T: Stream + for<'a> Sink<&'a [u8]>> ShadowsocksStream<T> {
    pub fn new(inner: T, max_chunk_size: usize) -> Self {
        Self {
            inner,
            max_chunk_size,
            current_chunk: None,
        }
    }
}

impl<T> AsyncRead for ShadowsocksStream<T>
where
    T: Stream<Item = io::Result<Bytes>> + for<'a> Sink<&'a [u8]> + Unpin,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if let Some(ref mut chunk) = self.current_chunk {
                let len = chunk.len().min(buf.remaining());
                buf.put_slice(&chunk[..len]);
                chunk.advance(len);
                if chunk.is_empty() {
                    self.current_chunk = None;
                }
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut self.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(chunk))) => self.current_chunk = Some(chunk),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl<T> AsyncWrite for ShadowsocksStream<T>
where
    T: Stream + for<'a> Sink<&'a [u8], Error = io::Error> + Unpin,
{
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let len = buf.len().min(self.max_chunk_size);
        let mut inner = Pin::new(&mut self.inner);
        match inner.as_mut().poll_ready(cx) {
            Poll::Ready(Ok(())) => Poll::Ready(inner.start_send(&buf[..len]).map(|()| len)),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_close(cx)
    }
}
