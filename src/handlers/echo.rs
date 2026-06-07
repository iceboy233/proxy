use std::io;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

use crate::{
    constants::{DATAGRAM_BUFFER_SIZE, STREAM_BUFFER_SIZE},
    traits::{
        AsyncDatagram, AsyncRecvFromExt, AsyncSendToExt, AsyncStream, DatagramHandler,
        StreamHandler,
    },
};

pub struct EchoHandler;

#[async_trait]
impl StreamHandler for EchoHandler {
    async fn handle_stream(
        &self,
        stream: &mut (dyn AsyncStream + Send + Sync + Unpin),
    ) -> io::Result<()> {
        let mut buf = Box::new_uninit_slice(STREAM_BUFFER_SIZE);
        loop {
            let mut read_buf = ReadBuf::uninit(buf.as_mut());
            stream.read_buf(&mut read_buf).await?;
            let filled = read_buf.filled();
            if filled.is_empty() {
                return Ok(());
            }
            stream.write_all(filled).await?
        }
    }
}

#[async_trait]
impl DatagramHandler for EchoHandler {
    async fn handle_datagram(
        &self,
        datagram: &(dyn AsyncDatagram + Send + Sync + Unpin),
    ) -> io::Result<()> {
        let mut buf = Box::new_uninit_slice(DATAGRAM_BUFFER_SIZE);
        loop {
            let mut read_buf = ReadBuf::uninit(buf.as_mut());
            if let Ok(addr) = datagram.recv_from(&mut read_buf).await {
                _ = datagram.send_to(read_buf.filled(), addr).await;
            }
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
        let (mut server, mut client) = duplex(STREAM_BUFFER_SIZE);
        tokio::spawn(async move {
            _ = handler.handle_stream(&mut server).await;
        });

        let payload = b"test echo stream";
        client.write_all(payload).await.unwrap();

        let mut buf = vec![0u8; payload.len()].into_boxed_slice();
        client.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf.as_ref(), payload);
    }

    #[tokio::test]
    async fn test_echo_datagram() {
        let handler = EchoHandler;
        let mut server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();
        tokio::spawn(async move {
            _ = handler.handle_datagram(&mut server).await;
        });

        let payload = b"test echo datagram";
        client.send_to(payload, server_addr).await.unwrap();

        let mut buf = vec![0u8; DATAGRAM_BUFFER_SIZE].into_boxed_slice();
        let (n, _) = client.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(&buf[..n], payload);
    }
}
