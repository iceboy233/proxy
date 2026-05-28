use std::{
    io,
    net::SocketAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};

use async_trait::async_trait;
use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::traits::{Connector, Datagram, DatagramConnector, Stream, StreamConnector};

pub struct SocksConnector {
    connector: Arc<dyn Connector + Send + Sync + Unpin>,
    server: SocketAddr,
}

impl SocksConnector {
    pub fn new(connector: Arc<dyn Connector + Send + Sync + Unpin>, server: SocketAddr) -> Self {
        Self { connector, server }
    }

    async fn method_selection(
        &self,
        src: &mut BytesMut,
    ) -> io::Result<Box<dyn Stream + Send + Sync + Unpin>> {
        let mut stream = self.connector.connect(self.server, &[5, 1, 0]).await?;

        while src.len() < 2 {
            stream.read_buf(src).await?;
        }
        if src[0] != 5 {
            return Err(io::ErrorKind::Unsupported.into());
        }
        if src[1] != 0 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        src.advance(2);
        Ok(stream)
    }

    async fn request(
        &self,
        stream: &mut (dyn Stream + Send + Sync + Unpin),
        src: &mut BytesMut,
        endpoint: SocketAddr,
        initial_data: &[u8],
    ) -> io::Result<()> {
        let mut dst = match endpoint {
            SocketAddr::V4(addr) => {
                let mut dst = BytesMut::with_capacity(10);
                dst.put_slice(&[5, 1, 0, 1]);
                dst.put_slice(&addr.ip().octets());
                dst.put_u16(addr.port());
                dst
            }
            SocketAddr::V6(addr) => {
                let mut dst = BytesMut::with_capacity(22);
                dst.put_slice(&[5, 1, 0, 4]);
                dst.put_slice(&addr.ip().octets());
                dst.put_u16(addr.port());
                dst
            }
        };
        dst.put_slice(initial_data);
        stream.write_all(&dst[..]).await?;

        self.request_reply(stream, src).await
    }

    async fn request_host(
        &self,
        stream: &mut (dyn Stream + Send + Sync + Unpin),
        src: &mut BytesMut,
        host: &str,
        port: u16,
        initial_data: &[u8],
    ) -> io::Result<()> {
        if host.len() > 255 {
            return Err(io::ErrorKind::InvalidData.into());
        }

        let mut dst = BytesMut::with_capacity(5 + host.len() + 2 + initial_data.len());
        dst.put_slice(&[5, 1, 0, 3, host.len() as u8]);
        dst.put_slice(host.as_bytes());
        dst.put_u16(port);
        dst.put_slice(initial_data);
        stream.write_all(&dst[..]).await?;

        self.request_reply(stream, src).await
    }

    async fn request_reply(
        &self,
        stream: &mut (dyn Stream + Send + Sync + Unpin),
        src: &mut BytesMut,
    ) -> io::Result<()> {
        while src.len() < 4 {
            stream.read_buf(src).await?;
        }
        if src[0] != 5 {
            return Err(io::ErrorKind::Unsupported.into());
        }
        if src[1] != 0 {
            let kind = match src[1] {
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
        match src[3] {
            1 => {
                // ipv4
                while src.len() < 10 {
                    stream.read_buf(src).await?;
                }
                src.advance(10);
            }
            4 => {
                // ipv6
                while src.len() < 22 {
                    stream.read_buf(src).await?;
                }
                src.advance(22);
            }
            3 => {
                // host
                while src.len() < 5 {
                    stream.read_buf(src).await?;
                }
                let len = src[4] as usize;
                while src.len() < 5 + len + 2 {
                    stream.read_buf(src).await?;
                }
                src.advance(5 + len + 2);
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
    ) -> io::Result<Box<dyn Stream + Send + Sync + Unpin>> {
        let mut src = BytesMut::with_capacity(64);
        let mut stream = self.method_selection(&mut src).await?;
        self.request(&mut stream, &mut src, endpoint, initial_data)
            .await?;
        Ok(Box::new(TcpStream { stream, src }))
    }

    async fn connect_host(
        &self,
        host: &str,
        port: u16,
        initial_data: &[u8],
    ) -> io::Result<Box<dyn Stream + Send + Sync + Unpin>> {
        let mut src = BytesMut::with_capacity(64);
        let mut stream = self.method_selection(&mut src).await?;
        self.request_host(&mut stream, &mut src, host, port, initial_data)
            .await?;
        Ok(Box::new(TcpStream { stream, src }))
    }
}

#[async_trait]
impl DatagramConnector for SocksConnector {
    async fn bind(
        &self,
        _endpoint: SocketAddr,
    ) -> io::Result<Box<dyn Datagram + Send + Sync + Unpin>> {
        Err(io::Error::other("datagram is not supported yet"))
    }
}

struct TcpStream {
    stream: Box<dyn Stream + Send + Sync + Unpin>,
    src: BytesMut,
}

impl AsyncRead for TcpStream {
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

impl AsyncWrite for TcpStream {
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
