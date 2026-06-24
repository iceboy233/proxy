use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::{
    traits::{AsyncDatagram, AsyncStream, Connector, DatagramConnector, StreamConnector},
    util::AsyncReadBufExt,
};

pub struct SocksConnector {
    connector: Arc<dyn Connector + Send + Sync>,
    server: SocketAddr,
}

impl SocksConnector {
    pub fn new(connector: Arc<dyn Connector + Send + Sync>, server: SocketAddr) -> Self {
        Self { connector, server }
    }

    async fn method_selection(
        &self,
        src: &mut BytesMut,
    ) -> io::Result<Box<dyn AsyncStream + Send + Sync + Unpin>> {
        let mut stream = self.connector.connect(self.server, &[5, 1, 0]).await?;

        stream.read_at_least(src, 2).await?;
        if src.get_u8() != 5 {
            return Err(io::ErrorKind::Unsupported.into());
        }
        if src.get_u8() != 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        Ok(stream)
    }

    async fn request(
        &self,
        stream: &mut (dyn AsyncStream + Send + Sync + Unpin),
        src: &mut BytesMut,
        endpoint: SocketAddr,
        initial_data: &[u8],
    ) -> io::Result<()> {
        let mut dst = match endpoint {
            SocketAddr::V4(addr) => {
                let mut dst = BytesMut::with_capacity(10 + initial_data.len());
                dst.put_slice(&[5, 1, 0, 1]);
                dst.put_u32(addr.ip().to_bits());
                dst.put_u16(addr.port());
                dst
            }
            SocketAddr::V6(addr) => {
                let mut dst = BytesMut::with_capacity(22 + initial_data.len());
                dst.put_slice(&[5, 1, 0, 4]);
                dst.put_u128(addr.ip().to_bits());
                dst.put_u16(addr.port());
                dst
            }
        };
        dst.put_slice(initial_data);
        stream.write_all(&dst).await?;
        stream.flush().await?;

        self.request_reply(stream, src).await
    }

    async fn request_host(
        &self,
        stream: &mut (dyn AsyncStream + Send + Sync + Unpin),
        src: &mut BytesMut,
        host: &str,
        port: u16,
        initial_data: &[u8],
    ) -> io::Result<()> {
        let mut dst = BytesMut::with_capacity(5 + host.len() + 2 + initial_data.len());
        dst.put_slice(&[5, 1, 0, 3]);
        dst.put_u8(
            host.len()
                .try_into()
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, ""))?,
        );
        dst.put_slice(host.as_bytes());
        dst.put_u16(port);
        dst.put_slice(initial_data);
        stream.write_all(&dst).await?;
        stream.flush().await?;

        self.request_reply(stream, src).await
    }

    async fn request_reply(
        &self,
        stream: &mut (dyn AsyncStream + Send + Sync + Unpin),
        src: &mut BytesMut,
    ) -> io::Result<()> {
        stream.read_at_least(src, 4).await?;
        if src.get_u8() != 5 {
            return Err(io::ErrorKind::Unsupported.into());
        }
        let rep = src.get_u8();
        if rep != 0 {
            let kind = match rep {
                1 => io::ErrorKind::ConnectionAborted,
                2 => io::ErrorKind::PermissionDenied,
                3 => io::ErrorKind::NetworkUnreachable,
                4 => io::ErrorKind::HostUnreachable,
                5 => io::ErrorKind::ConnectionRefused,
                6 => io::ErrorKind::TimedOut,
                7 => io::ErrorKind::Unsupported,
                8 => io::ErrorKind::AddrNotAvailable,
                _ => io::ErrorKind::Other,
            };
            return Err(io::Error::new(kind, ""));
        }
        src.get_u8();
        match src.get_u8() {
            // ipv4
            1 => {
                stream.read_at_least(src, 6).await?;
                src.advance(6);
            }
            // ipv6
            4 => {
                stream.read_at_least(src, 18).await?;
                src.advance(18);
            }
            // host
            3 => {
                stream.read_at_least(src, 1).await?;
                let len = src.get_u8() as usize;
                stream.read_at_least(src, len + 2).await?;
                src.advance(len + 2);
            }
            _ => {
                return Err(io::ErrorKind::InvalidData.into());
            }
        }
        Ok(())
    }
}

#[async_trait]
impl StreamConnector for SocksConnector {
    async fn connect(
        &self,
        endpoint: SocketAddr,
        initial_data: &[u8],
    ) -> io::Result<Box<dyn AsyncStream + Send + Sync + Unpin>> {
        let mut src = BytesMut::with_capacity(64);
        let mut stream = self.method_selection(&mut src).await?;
        self.request(&mut stream, &mut src, endpoint, initial_data)
            .await?;
        Ok(Box::new(SocksStream { stream, src }))
    }

    async fn connect_host(
        &self,
        host: &str,
        port: u16,
        initial_data: &[u8],
    ) -> io::Result<Box<dyn AsyncStream + Send + Sync + Unpin>> {
        let mut src = BytesMut::with_capacity(64);
        let mut stream = self.method_selection(&mut src).await?;
        self.request_host(&mut stream, &mut src, host, port, initial_data)
            .await?;
        Ok(Box::new(SocksStream { stream, src }))
    }
}

#[async_trait]
impl DatagramConnector for SocksConnector {
    async fn bind(
        &self,
        _endpoint: SocketAddr,
    ) -> io::Result<Box<dyn AsyncDatagram + Send + Sync + Unpin>> {
        Err(io::Error::other("datagram is not supported yet"))
    }
}

struct SocksStream {
    stream: Box<dyn AsyncStream + Send + Sync + Unpin>,
    src: BytesMut,
}

impl AsyncRead for SocksStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if !self.src.is_empty() {
            let len = buf.remaining().min(self.src.len());
            buf.put_slice(&self.src[..len]);
            self.src.advance(len);
            if self.src.is_empty() {
                self.src = BytesMut::new();
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for SocksStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
