use std::{
    io,
    net::{Ipv4Addr, Ipv6Addr, SocketAddrV4, SocketAddrV6},
    sync::Arc,
};

use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use tokio::io::{copy_bidirectional_with_sizes, AsyncWriteExt};

use crate::{
    constants::STREAM_BUFFER_SIZE,
    traits::{AsyncDatagram, AsyncStream, Connector, DatagramHandler, StreamHandler},
    util::AsyncReadBufExt,
};

pub struct SocksHandler {
    connector: Arc<dyn Connector + Send + Sync>,
}

impl SocksHandler {
    pub fn new(connector: Arc<dyn Connector + Send + Sync>) -> Self {
        Self { connector }
    }

    async fn method_selection(
        &self,
        stream: &mut (dyn AsyncStream + Send + Sync + Unpin),
        src: &mut BytesMut,
    ) -> io::Result<()> {
        stream.read_at_least(src, 2).await?;
        if src.get_u8() != 5 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let nmethods = src.get_u8() as usize;
        stream.read_at_least(src, nmethods).await?;
        let methods = &src[..nmethods];
        if !methods.contains(&0) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        src.advance(nmethods);
        stream.write_all(&[5, 0]).await?;
        stream.flush().await
    }

    async fn request(
        &self,
        stream: &mut (dyn AsyncStream + Send + Sync + Unpin),
        src: &mut BytesMut,
    ) -> io::Result<Box<dyn AsyncStream + Send + Sync + Unpin>> {
        stream.read_at_least(src, 4).await?;
        if src.get_u8() != 5 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        if src.get_u8() != 1 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        src.get_u8();
        let atyp = src.get_u8();
        let remote_stream = match atyp {
            1 => self.connect_ipv4(stream, src).await,
            4 => self.connect_ipv6(stream, src).await,
            3 => self.connect_host(stream, src).await,
            _ => Err(io::ErrorKind::InvalidData.into()),
        }?;
        stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        stream.flush().await?;
        Ok(remote_stream)
    }

    async fn connect_ipv4(
        &self,
        stream: &mut (dyn AsyncStream + Send + Sync + Unpin),
        src: &mut BytesMut,
    ) -> io::Result<Box<dyn AsyncStream + Send + Sync + Unpin>> {
        stream.read_at_least(src, 6).await?;
        let ip = Ipv4Addr::from(src.get_u32());
        let port = src.get_u16();
        let addr = SocketAddrV4::new(ip, port).into();
        self.connector.connect(addr, &src).await
    }

    async fn connect_ipv6(
        &self,
        stream: &mut (dyn AsyncStream + Send + Sync + Unpin),
        src: &mut BytesMut,
    ) -> io::Result<Box<dyn AsyncStream + Send + Sync + Unpin>> {
        stream.read_at_least(src, 18).await?;
        let ip = Ipv6Addr::from(src.get_u128());
        let port = src.get_u16();
        let addr = SocketAddrV6::new(ip, port, 0, 0).into();
        self.connector.connect(addr, &src).await
    }

    async fn connect_host(
        &self,
        stream: &mut (dyn AsyncStream + Send + Sync + Unpin),
        src: &mut BytesMut,
    ) -> io::Result<Box<dyn AsyncStream + Send + Sync + Unpin>> {
        stream.read_at_least(src, 1).await?;
        let host_len = src.get_u8() as usize;
        stream.read_at_least(src, host_len + 2).await?;
        let host = str::from_utf8(&src[..host_len])
            .map_err(|_| io::Error::from(io::ErrorKind::InvalidData))?
            .to_string();
        src.advance(host_len);
        let port = src.get_u16();
        self.connector.connect_host(&host, port, &src).await
    }
}

#[async_trait]
impl StreamHandler for SocksHandler {
    async fn handle_stream(
        &self,
        stream: &mut (dyn AsyncStream + Send + Sync + Unpin),
    ) -> io::Result<()> {
        let mut src = BytesMut::with_capacity(64);
        self.method_selection(stream, &mut src).await?;
        let mut remote_stream = self.request(stream, &mut src).await?;
        copy_bidirectional_with_sizes(
            stream,
            &mut remote_stream,
            STREAM_BUFFER_SIZE,
            STREAM_BUFFER_SIZE,
        )
        .await?;
        Ok(())
    }
}

#[async_trait]
impl DatagramHandler for SocksHandler {
    async fn handle_datagram(
        &self,
        _datagram: &(dyn AsyncDatagram + Send + Sync + Unpin),
    ) -> io::Result<()> {
        Err(io::Error::other("datagram is not supported yet"))
    }
}
