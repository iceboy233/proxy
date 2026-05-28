use std::{
    io,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};

use async_trait::async_trait;
use bytes::{Buf, BytesMut};
use tokio::io::{copy_bidirectional_with_sizes, AsyncReadExt, AsyncWriteExt};

use crate::{
    constants::STREAM_BUFFER_SIZE,
    traits::{Connector, Datagram, DatagramHandler, Stream, StreamHandler},
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
        stream: &mut (dyn Stream + Send + Sync + Unpin),
        src: &mut BytesMut,
    ) -> io::Result<()> {
        while src.len() < 2 {
            stream.read_buf(src).await?;
        }
        if src[0] != 5 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let nmethods = src[1] as usize;
        src.advance(2);

        while src.len() < nmethods {
            stream.read_buf(src).await?;
        }
        let methods = &src[..nmethods];
        if !methods.contains(&0) {
            return Err(io::ErrorKind::InvalidData.into());
        }
        src.advance(nmethods);
        stream.write_all(&[5, 0]).await
    }

    async fn request(
        &self,
        stream: &mut (dyn Stream + Send + Sync + Unpin),
        src: &mut BytesMut,
    ) -> io::Result<Box<dyn Stream + Send + Sync + Unpin>> {
        while src.len() < 4 {
            stream.read_buf(src).await?;
        }
        if src[0] != 5 || src[1] != 1 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let atyp = src[3];
        src.advance(4);
        let remote_stream = match atyp {
            1 => self.connect_ipv4(stream, src).await,
            4 => self.connect_ipv6(stream, src).await,
            3 => self.connect_host(stream, src).await,
            _ => Err(io::ErrorKind::InvalidData.into()),
        }?;
        stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        Ok(remote_stream)
    }

    async fn connect_ipv4(
        &self,
        stream: &mut (dyn Stream + Send + Sync + Unpin),
        src: &mut BytesMut,
    ) -> io::Result<Box<dyn Stream + Send + Sync + Unpin>> {
        while src.len() < 6 {
            stream.read_buf(src).await?;
        }
        let ip = Ipv4Addr::from_octets(src[0..4].try_into().unwrap());
        let port = u16::from_be_bytes(src[4..6].try_into().unwrap());
        src.advance(6);

        self.connector
            .connect(SocketAddr::new(IpAddr::V4(ip), port), &src[..])
            .await
    }

    async fn connect_ipv6(
        &self,
        stream: &mut (dyn Stream + Send + Sync + Unpin),
        src: &mut BytesMut,
    ) -> io::Result<Box<dyn Stream + Send + Sync + Unpin>> {
        while src.len() < 18 {
            stream.read_buf(src).await?;
        }
        let ip = Ipv6Addr::from_octets(src[0..16].try_into().unwrap());
        let port = u16::from_be_bytes(src[16..18].try_into().unwrap());
        src.advance(18);

        self.connector
            .connect(SocketAddr::new(IpAddr::V6(ip), port), &src[..])
            .await
    }

    async fn connect_host(
        &self,
        stream: &mut (dyn Stream + Send + Sync + Unpin),
        src: &mut BytesMut,
    ) -> io::Result<Box<dyn Stream + Send + Sync + Unpin>> {
        while src.len() < 1 {
            stream.read_buf(src).await?;
        }
        let host_length = src[0] as usize;
        src.advance(1);

        while src.len() < host_length + 2 {
            stream.read_buf(src).await?;
        }
        let host = str::from_utf8(&src[..host_length])
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, ""))?
            .to_string();
        let port = u16::from_be_bytes(src[host_length..host_length + 2].try_into().unwrap());
        src.advance(host_length + 2);

        self.connector.connect_host(&host, port, &src[..]).await
    }
}

#[async_trait]
impl StreamHandler for SocksHandler {
    async fn handle_stream(
        &self,
        stream: &mut (dyn Stream + Send + Sync + Unpin),
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
        _datagram: &(dyn Datagram + Send + Sync + Unpin),
    ) -> io::Result<()> {
        Err(io::Error::other("datagram is not supported yet"))
    }
}
