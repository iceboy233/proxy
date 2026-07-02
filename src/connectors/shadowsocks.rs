use std::{io, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use bytes::{BufMut, BytesMut};
use tokio_util::codec::{Encoder, Framed, FramedParts};

use crate::{
    constants::STREAM_BUFFER_SIZE,
    protocols::shadowsocks::{Codec, CodecKind, MasterKey, Method, ShadowsocksStream},
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
        codec: Codec,
    ) -> io::Result<Box<dyn AsyncStream + Send + Sync + Unpin>> {
        let remote_stream = self.connector.connect(self.server, &write_buf).await?;
        write_buf.clear();
        let mut framed_parts = FramedParts::new(remote_stream, codec);
        framed_parts.read_buf = BytesMut::with_capacity(STREAM_BUFFER_SIZE);
        framed_parts.write_buf = write_buf;
        let framed = Framed::from_parts(framed_parts);
        let stream = ShadowsocksStream::new(framed, self.method.max_chunk_size());
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl StreamConnector for ShadowsocksConnector {
    async fn connect(
        &self,
        endpoint: SocketAddr,
        initial_data: &[u8],
    ) -> io::Result<Box<dyn AsyncStream + Send + Sync + Unpin>> {
        let mut write_buf = BytesMut::with_capacity(STREAM_BUFFER_SIZE);
        write_buf.resize(self.method.salt_len(), 0);
        rand::fill(&mut write_buf);
        // TODO: put salt into filter
        let mut codec = Codec::new(CodecKind::Client, self.method, self.master_key, &write_buf);

        let mut dst = BytesMut::new();
        match endpoint {
            SocketAddr::V4(addr) => {
                dst.put_u8(1); // ipv4
                dst.put_u32(addr.ip().to_bits());
                dst.put_u16(addr.port());
            }
            SocketAddr::V6(addr) => {
                dst.put_u8(4); // ipv6
                dst.put_u128(addr.ip().to_bits());
                dst.put_u16(addr.port());
            }
        }
        if self.method.is_spec_2022() {
            let padding_len = rand::random_range(self.min_padding_len..self.max_padding_len);
            dst.put_u16(padding_len);
            let padding_offset = dst.len();
            dst.put_bytes(0, padding_len as usize);
            rand::fill(&mut dst[padding_offset..]);
        }
        dst.put_slice(initial_data);
        codec.encode(&dst, &mut write_buf).unwrap();

        self.create_stream(write_buf, codec).await
    }

    async fn connect_host(
        &self,
        host: &str,
        port: u16,
        initial_data: &[u8],
    ) -> io::Result<Box<dyn AsyncStream + Send + Sync + Unpin>> {
        let mut write_buf = BytesMut::with_capacity(STREAM_BUFFER_SIZE);
        write_buf.resize(self.method.salt_len(), 0);
        rand::fill(&mut write_buf);
        // TODO: put salt into filter
        let mut codec = Codec::new(CodecKind::Client, self.method, self.master_key, &write_buf);

        let mut dst = BytesMut::new();
        dst.put_u8(3); // host
        dst.put_u8(
            host.len()
                .try_into()
                .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?,
        );
        dst.put_slice(host.as_bytes());
        dst.put_u16(port);
        if self.method.is_spec_2022() {
            let padding_len = rand::random_range(self.min_padding_len..self.max_padding_len);
            dst.put_u16(padding_len);
            let padding_offset = dst.len();
            dst.put_bytes(0, padding_len as usize);
            rand::fill(&mut dst[padding_offset..]);
        }
        dst.put_slice(initial_data);
        codec.encode(&dst, &mut write_buf).unwrap();
        dst.clear();

        self.create_stream(write_buf, codec).await
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
