use std::{io, net::SocketAddr};

use async_trait::async_trait;
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpStream, UdpSocket};

use crate::traits::{Datagram, DatagramConnector, Stream, StreamConnector};

#[derive(Clone)]
pub struct SystemConnector {
    tcp_no_delay: bool,
}

#[async_trait]
impl StreamConnector for SystemConnector {
    async fn connect(
        &self,
        endpoint: SocketAddr,
        initial_data: &[u8],
    ) -> io::Result<Box<dyn Stream>> {
        let mut stream = TcpStream::connect(endpoint).await?;
        if self.tcp_no_delay {
            // TODO: log error when failed
            let _ = stream.set_nodelay(true);
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
    ) -> io::Result<Box<dyn Stream>> {
        // TODO: use asynchronous name resolver
        let mut stream = TcpStream::connect((host, port)).await?;
        if self.tcp_no_delay {
            // TODO: log error when failed
            let _ = stream.set_nodelay(true);
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
    async fn bind(&self, endpoint: SocketAddr) -> io::Result<Box<dyn Datagram>> {
        let socket = UdpSocket::bind(endpoint).await?;
        Ok(Box::new(socket))
    }
}
