use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::{Buf, BufMut, Bytes, BytesMut};
use futures_util::{Sink, Stream};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_util::codec::{Decoder, Encoder, Framed, FramedParts};

use crate::{
    constants::STREAM_BUFFER_SIZE,
    protocols::shadowsocks::{
        timestamp, DecryptionKey, EncryptionKey, MasterKey, Method, MAX_SALT_LEN,
    },
    traits::{AsyncDatagram, AsyncStream, Connector, DatagramConnector, StreamConnector},
};

pub struct ShadowsocksConnector {
    connector: Arc<dyn Connector + Send + Sync>,
    server: SocketAddr,
    method: Method,
    master_key: MasterKey,
    min_padding_len: u16,
    max_padding_len: u16,
}

impl ShadowsocksConnector {
    pub fn new(
        connector: Arc<dyn Connector + Send + Sync>,
        server: SocketAddr,
        method: Method,
        master_key: MasterKey,
        min_padding_len: u16,
        max_padding_len: u16,
    ) -> Self {
        Self {
            connector,
            server,
            method,
            master_key,
            min_padding_len,
            max_padding_len,
        }
    }

    async fn create_stream(
        &self,
        mut write_buf: BytesMut,
        encryption_key: EncryptionKey,
    ) -> io::Result<Box<dyn AsyncStream + Send + Sync + Unpin>> {
        let stream = self.connector.connect(self.server, &write_buf).await?;
        write_buf.clear();
        let codec = Codec {
            method: self.method,
            master_key: self.master_key,
            encryption_key,
            decode_state: DecodeState::Init,
            decryption_key: None,
        };
        let mut framed_parts = FramedParts::new(stream, codec);
        framed_parts.read_buf = BytesMut::with_capacity(STREAM_BUFFER_SIZE);
        framed_parts.write_buf = write_buf;
        let framed = Framed::from_parts(framed_parts);
        Ok(Box::new(TcpStream {
            framed,
            method: self.method,
            current_chunk: None,
        }))
    }
}

#[async_trait]
impl StreamConnector for ShadowsocksConnector {
    async fn connect(
        &self,
        endpoint: SocketAddr,
        initial_data: &[u8],
    ) -> io::Result<Box<dyn AsyncStream + Send + Sync + Unpin>> {
        let mut dst = BytesMut::with_capacity(STREAM_BUFFER_SIZE);
        let salt = &mut [0u8; MAX_SALT_LEN][..self.method.salt_len()];
        rand::fill(salt);
        let mut encryption_key = EncryptionKey::new(self.method, &self.master_key, salt);
        dst.put_slice(salt);
        // TODO: put salt into filter

        // Request fixed-length header.
        let chunk_offset = dst.len();
        let mut header_len = if endpoint.is_ipv4() { 7 } else { 19 };
        // TODO: support legacy methods
        dst.put_u8(0);
        dst.put_u64(timestamp());
        let padding_len = rand::random_range(self.min_padding_len..self.max_padding_len);
        header_len += 2 + padding_len as usize;
        header_len += initial_data.len();
        dst.put_u16(
            header_len
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, ""))?,
        );
        let tag = encryption_key.encrypt(&mut dst[chunk_offset..]);
        dst.put_slice(tag.as_ref());

        // Request variable-length header.
        let chunk_offset = dst.len();
        match endpoint {
            SocketAddr::V4(addr) => {
                dst.put_u8(1); // ipv4
                dst.put_slice(addr.ip().octets().as_slice());
                dst.put_u16(addr.port());
            }
            SocketAddr::V6(addr) => {
                dst.put_u8(4); // ipv6
                dst.put_slice(addr.ip().octets().as_slice());
                dst.put_u16(addr.port());
            }
        }
        // TODO: support legacy methods
        dst.put_u16(padding_len);
        let padding_offset = dst.len();
        dst.put_bytes(0, padding_len as usize);
        rand::fill(&mut dst[padding_offset..]);
        dst.put_slice(initial_data);
        let tag = encryption_key.encrypt(&mut dst[chunk_offset..]);
        dst.put_slice(tag.as_ref());

        self.create_stream(dst, encryption_key).await
    }

    async fn connect_host(
        &self,
        host: &str,
        port: u16,
        initial_data: &[u8],
    ) -> io::Result<Box<dyn AsyncStream + Send + Sync + Unpin>> {
        let mut dst = BytesMut::with_capacity(STREAM_BUFFER_SIZE);
        let salt = &mut [0u8; MAX_SALT_LEN][..self.method.salt_len()];
        rand::fill(salt);
        let mut encryption_key = EncryptionKey::new(self.method, &self.master_key, salt);
        dst.put_slice(salt);
        // TODO: put salt into filter

        // Request fixed-length header.
        let chunk_offset = dst.len();
        let mut header_len = 4 + host.len();
        // TODO: support legacy methods
        dst.put_u8(0);
        dst.put_u64(timestamp());
        let padding_len = rand::random_range(self.min_padding_len..self.max_padding_len);
        header_len += 2 + padding_len as usize;
        header_len += initial_data.len();
        dst.put_u16(
            header_len
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, ""))?,
        );
        let tag = encryption_key.encrypt(&mut dst[chunk_offset..]);
        dst.put_slice(tag.as_ref());

        // Request variable-length header.
        let chunk_offset = dst.len();
        dst.put_u8(3); // host
        dst.put_u8(
            host.len()
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, ""))?,
        );
        dst.put_slice(host.as_bytes());
        dst.put_u16(port);
        // TODO: support legacy methods
        dst.put_u16(padding_len);
        let padding_offset = dst.len();
        dst.put_bytes(0, padding_len as usize);
        rand::fill(&mut dst[padding_offset..]);
        dst.put_slice(initial_data);
        let tag = encryption_key.encrypt(&mut dst[chunk_offset..]);
        dst.put_slice(tag.as_ref());

        self.create_stream(dst, encryption_key).await
    }
}

#[async_trait]
impl DatagramConnector for ShadowsocksConnector {
    async fn bind(
        &self,
        _endpoint: SocketAddr,
    ) -> io::Result<Box<dyn AsyncDatagram + Send + Sync + Unpin>> {
        Err(io::Error::other("datagram is not supported yet"))
    }
}

struct TcpStream {
    framed: Framed<Box<dyn AsyncStream + Send + Sync + Unpin>, Codec>,
    method: Method,
    current_chunk: Option<Bytes>,
}

impl AsyncRead for TcpStream {
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
            match Pin::new(&mut self.framed).poll_next(cx) {
                Poll::Ready(Some(Ok(chunk))) => self.current_chunk = Some(chunk),
                Poll::Ready(Some(Err(e))) => return Poll::Ready(Err(e)),
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for TcpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match Pin::new(&mut self.framed).poll_ready(cx) {
            Poll::Ready(Ok(())) => {
                let len = buf.len().min(self.method.max_chunk_size());
                let chunk = Bytes::copy_from_slice(&buf[..len]);
                Poll::Ready(Pin::new(&mut self.framed).start_send(chunk).map(|()| len))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.framed).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.framed).poll_close(cx)
    }
}

struct Codec {
    method: Method,
    master_key: MasterKey,
    encryption_key: EncryptionKey,
    decryption_key: Option<DecryptionKey>,
    decode_state: DecodeState,
}

enum DecodeState {
    Init,
    Header,
    Length,
    Payload(usize),
    Discard,
}

impl Encoder<Bytes> for Codec {
    type Error = io::Error;

    fn encode(&mut self, chunk: Bytes, dst: &mut BytesMut) -> Result<(), Self::Error> {
        let offset = dst.len();
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
        let salt_len = self.method.salt_len();
        let tag_len = self.method.tag_len();
        loop {
            match self.decode_state {
                DecodeState::Init => {
                    if src.len() < salt_len {
                        return Ok(None);
                    }
                    let salt = &src[..salt_len];
                    self.decryption_key =
                        Some(DecryptionKey::new(self.method, &self.master_key, salt));
                    src.advance(salt_len);
                    // TODO: goto Length for legacy methods
                    self.decode_state = DecodeState::Header;
                }
                DecodeState::Header => {
                    let read_len = 1 + 8 + salt_len + 2 + tag_len;
                    if src.len() < read_len {
                        return Ok(None);
                    }
                    let Some(chunk) = self
                        .decryption_key
                        .as_mut()
                        .unwrap()
                        .decrypt(&mut src[..read_len])
                    else {
                        self.decode_state = DecodeState::Discard;
                        continue;
                    };
                    let mut chunk: &[u8] = chunk;
                    if chunk.get_u8() != 1 {
                        self.decode_state = DecodeState::Discard;
                        continue;
                    }
                    chunk.get_u64(); // TODO: verify timestamp
                    let _salt = &chunk[..salt_len];
                    // TODO: verify salt
                    chunk = &chunk[salt_len..];
                    let payload_len = chunk.get_u16() as usize;
                    src.advance(read_len);
                    self.decode_state = DecodeState::Payload(payload_len);
                }
                DecodeState::Length => {
                    let read_len = 2 + tag_len;
                    if src.len() < read_len {
                        return Ok(None);
                    }
                    let Some(chunk) = self
                        .decryption_key
                        .as_mut()
                        .unwrap()
                        .decrypt(&mut src[..read_len])
                    else {
                        self.decode_state = DecodeState::Discard;
                        continue;
                    };
                    let mut chunk: &[u8] = chunk;
                    let payload_len = chunk.get_u16() as usize;
                    src.advance(read_len);
                    self.decode_state = DecodeState::Payload(payload_len);
                }
                DecodeState::Payload(len) => {
                    let read_len = len + tag_len;
                    if src.len() < read_len {
                        return Ok(None);
                    }
                    let Some(chunk) = self
                        .decryption_key
                        .as_mut()
                        .unwrap()
                        .decrypt(&mut src[..read_len])
                    else {
                        self.decode_state = DecodeState::Discard;
                        continue;
                    };
                    let bytes = Bytes::copy_from_slice(chunk);
                    src.advance(read_len);
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
