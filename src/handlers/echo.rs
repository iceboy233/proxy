use std::io;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

use crate::{
    constants::{DATAGRAM_BUFFER_SIZE, STREAM_BUFFER_SIZE},
    traits::{AsyncRecvFromExt, AsyncSendToExt, Datagram, DatagramHandler, Stream, StreamHandler},
};

#[derive(Clone)]
pub struct EchoHandler;

#[async_trait]
impl StreamHandler for EchoHandler {
    async fn handle_stream(&self, stream: Box<dyn Stream>) -> io::Result<()> {
        let mut s = Box::into_pin(stream);
        let mut buf = Box::new_uninit_slice(STREAM_BUFFER_SIZE);
        loop {
            let mut read_buf = ReadBuf::uninit(&mut *buf);
            s.read_buf(&mut read_buf).await?;
            let filled = read_buf.filled();
            if filled.is_empty() {
                return Ok(());
            }
            s.write_all(filled).await?
        }
    }
}

#[async_trait]
impl DatagramHandler for EchoHandler {
    async fn handle_datagram(&self, datagram: Box<dyn Datagram>) -> io::Result<()> {
        let mut d = Box::into_pin(datagram);
        let mut buf = Box::new_uninit_slice(DATAGRAM_BUFFER_SIZE);
        loop {
            let mut read_buf = ReadBuf::uninit(&mut *buf);
            let addr = d.recv_from(&mut read_buf).await?;
            d.send_to(read_buf.filled(), addr).await?;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{duplex, AsyncReadExt, AsyncWriteExt};
    use tokio::net::UdpSocket;

    #[tokio::test]
    async fn test_echo_stream() {
        let handler = EchoHandler;
        let (server, mut client) = duplex(STREAM_BUFFER_SIZE);
        tokio::spawn(async move {
            let _ = handler.handle_stream(Box::new(server)).await;
        });

        let payload = b"test echo stream";
        client.write_all(payload).await.unwrap();

        let mut buf = vec![0u8; payload.len()].into_boxed_slice();
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf[..], payload);
    }

    #[tokio::test]
    async fn test_echo_datagram() {
        let handler = EchoHandler;
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            let _ = handler.handle_datagram(Box::new(server)).await;
        });

        let payload = b"test echo datagram";
        client.send_to(payload, server_addr).await.unwrap();

        let mut buf = vec![0u8; DATAGRAM_BUFFER_SIZE].into_boxed_slice();
        let (n, _) = client.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(&buf[..n], payload);
    }
}
