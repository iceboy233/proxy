use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadBuf};

use crate::{
    constants::{DATAGRAM_BUFFER_SIZE, STREAM_BUFFER_SIZE},
    traits::{AsyncRecvFromExt, AsyncSendToExt, Datagram, DatagramHandler, Stream, StreamHandler},
};

pub struct EchoHandler;

impl StreamHandler for EchoHandler {
    fn handle_stream(&self, stream: Box<dyn Stream>) {
        tokio::spawn(async move {
            let mut s = Box::into_pin(stream);
            let mut buf = Box::new_uninit_slice(STREAM_BUFFER_SIZE);
            loop {
                let mut read_buf = ReadBuf::uninit(&mut *buf);
                match s.read_buf(&mut read_buf).await {
                    Ok(_) => {
                        if let Err(_) = s.write_all(read_buf.filled()).await {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }
}

impl DatagramHandler for EchoHandler {
    fn handle_datagram(&self, datagram: Box<dyn Datagram>) {
        tokio::spawn(async move {
            let mut d = Box::into_pin(datagram);
            let mut buf = Box::new_uninit_slice(DATAGRAM_BUFFER_SIZE);
            loop {
                let mut read_buf = ReadBuf::uninit(&mut *buf);
                match d.recv_from(&mut read_buf).await {
                    Ok(addr) => {
                        if let Err(_) = d.send_to(read_buf.filled(), addr).await {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });
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
        handler.handle_stream(Box::new(server));

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
        handler.handle_datagram(Box::new(server));

        let payload = b"test echo datagram";
        client.send_to(payload, server_addr).await.unwrap();

        let mut buf = vec![0u8; DATAGRAM_BUFFER_SIZE].into_boxed_slice();
        let (n, _) = client.recv_from(&mut buf).await.unwrap();
        assert_eq!(n, payload.len());
        assert_eq!(&buf[..n], payload);
    }
}
