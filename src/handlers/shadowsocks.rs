use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use async_trait::async_trait;
use bytes::{Buf, Bytes, BytesMut};
use futures_util::StreamExt;
use tokio::io::copy_bidirectional_with_sizes;
use tokio_util::codec::{Framed, FramedParts};

use crate::{
    constants::STREAM_BUFFER_SIZE,
    protocols::shadowsocks::{Codec, CodecKind, MasterKey, Method, ShadowsocksStream},
    traits::{AsyncDatagram, AsyncStream, Connector, DatagramHandler, StreamHandler},
};

pub struct ShadowsocksHandler {
    connector: Arc<dyn Connector + Send + Sync>,
    method: Method,
    master_key: MasterKey,
}

impl ShadowsocksHandler {
    pub fn new(
        connector: Arc<dyn Connector + Send + Sync>,
        method: Method,
        master_key: MasterKey,
    ) -> Self {
        Self {
            connector,
            method,
            master_key,
        }
    }

    async fn connect_ipv4(
        &self,
        mut src: Bytes,
    ) -> io::Result<Box<dyn AsyncStream + Send + Sync + Unpin>> {
        if src.len() < 6 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let ip = Ipv4Addr::from(src.get_u32());
        let port = src.get_u16();
        if self.method.is_spec_2022() {
            if src.len() < 2 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let padding_len = src.get_u16() as usize;
            if src.len() < padding_len {
                return Err(io::ErrorKind::InvalidData.into());
            }
            src.advance(padding_len);
            if padding_len == 0 && src.is_empty() {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        self.connector
            .connect(SocketAddrV4::new(ip, port).into(), &src)
            .await
    }

    async fn connect_ipv6(
        &self,
        mut src: Bytes,
    ) -> io::Result<Box<dyn AsyncStream + Send + Sync + Unpin>> {
        if src.len() < 18 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let ip = Ipv6Addr::from(src.get_u128());
        let port = src.get_u16();
        if self.method.is_spec_2022() {
            if src.len() < 2 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let padding_len = src.get_u16() as usize;
            if src.len() < padding_len {
                return Err(io::ErrorKind::InvalidData.into());
            }
            src.advance(padding_len);
            if padding_len == 0 && src.is_empty() {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        self.connector
            .connect(SocketAddrV6::new(ip, port, 0, 0).into(), &src)
            .await
    }

    async fn connect_host(
        &self,
        mut src: Bytes,
    ) -> io::Result<Box<dyn AsyncStream + Send + Sync + Unpin>> {
        if src.len() < 1 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let host_len = src.get_u8() as usize;
        if src.len() < host_len + 2 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let host = str::from_utf8(&src[..host_len])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, ""))?
            .to_string();
        src.advance(host_len);
        let port = src.get_u16();
        if self.method.is_spec_2022() {
            if src.len() < 2 {
                return Err(io::ErrorKind::InvalidData.into());
            }
            let padding_len = src.get_u16() as usize;
            if src.len() < padding_len {
                return Err(io::ErrorKind::InvalidData.into());
            }
            src.advance(padding_len);
            if padding_len == 0 && src.is_empty() {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        self.connector.connect_host(&host, port, &src).await
    }
}

#[async_trait]
impl StreamHandler for ShadowsocksHandler {
    async fn handle_stream(
        &self,
        stream: &mut (dyn AsyncStream + Send + Sync + Unpin),
    ) -> io::Result<()> {
        let mut write_buf = BytesMut::with_capacity(STREAM_BUFFER_SIZE);
        write_buf.resize(self.method.salt_len(), 0);
        rand::fill(&mut write_buf);

        let codec = Codec::new(CodecKind::Server, self.method, self.master_key, &write_buf);
        let mut framed_parts = FramedParts::new(stream, codec);
        framed_parts.read_buf = BytesMut::with_capacity(STREAM_BUFFER_SIZE);
        framed_parts.write_buf = write_buf;
        let mut framed = Framed::from_parts(framed_parts);
        let mut header = framed
            .next()
            .await
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, ""))??;
        // TODO: put salt into filter
        if header.len() < 1 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let mut remote_stream = match header.get_u8() {
            1 => self.connect_ipv4(header).await,
            4 => self.connect_ipv6(header).await,
            3 => self.connect_host(header).await,
            _ => Err(io::ErrorKind::InvalidData.into()),
        }?;
        let mut stream = ShadowsocksStream::new(framed, self.method.max_chunk_size());
        copy_bidirectional_with_sizes(
            &mut stream,
            &mut remote_stream,
            STREAM_BUFFER_SIZE,
            STREAM_BUFFER_SIZE,
        )
        .await?;
        Ok(())
    }
}

#[async_trait]
impl DatagramHandler for ShadowsocksHandler {
    async fn handle_datagram(
        &self,
        _datagram: &(dyn AsyncDatagram + Send + Sync + Unpin),
    ) -> io::Result<()> {
        Err(io::Error::other("datagram is not supported yet"))
    }
}
