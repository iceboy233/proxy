use std::{io, net::SocketAddr};

use async_trait::async_trait;
use log::error;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};

use crate::traits::{AsyncDatagram, AsyncStream, DatagramConnector, StreamConnector};

pub struct SystemConnector {
    tcp_no_delay: bool,
}

impl SystemConnector {
    pub fn new(tcp_no_delay: bool) -> Self {
        Self { tcp_no_delay }
    }
}

#[async_trait]
impl StreamConnector for SystemConnector {
    async fn connect(
        &self,
        endpoint: SocketAddr,
        initial_data: &[u8],
    ) -> io::Result<Box<dyn AsyncStream + Send + Sync + Unpin>> {
        let mut stream = TcpStream::connect(endpoint).await?;
        if self.tcp_no_delay {
            if let Err(e) = stream.set_nodelay(true) {
                error!("set nodelay failed: {}", e);
            }
        }
        // TODO: support fastopen connect
        if !initial_data.is_empty() {
            stream.write_all(initial_data).await?;
        }
        Ok(Box::new(stream))
    }

    async fn connect_host(
        &self,
        host: &str,
        port: u16,
        initial_data: &[u8],
    ) -> io::Result<Box<dyn AsyncStream + Send + Sync + Unpin>> {
        // TODO: use asynchronous name resolver
        let mut stream = TcpStream::connect((host, port)).await?;
        if self.tcp_no_delay {
            if let Err(e) = stream.set_nodelay(true) {
                error!("set nodelay failed: {}", e);
            }
        }
        // TODO: support fastopen connect
        if !initial_data.is_empty() {
            stream.write_all(initial_data).await?;
        }
        Ok(Box::new(stream))
    }
}

#[async_trait]
impl DatagramConnector for SystemConnector {
    async fn bind(
        &self,
        endpoint: SocketAddr,
    ) -> io::Result<Box<dyn AsyncDatagram + Send + Sync + Unpin>> {
        let socket = UdpSocket::bind(endpoint).await?;
        Ok(Box::new(socket))
    }
}
