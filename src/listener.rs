use std::{io, net::SocketAddr, sync::Arc};

use log::error;
use tokio::net::{TcpListener, UdpSocket};

use crate::traits::Handler;

pub struct Listener {
    tcp_listener: TcpListener,
    udp_socket: Arc<UdpSocket>,
    tcp_no_delay: bool,
}

impl Listener {
    pub async fn bind(addr: SocketAddr, tcp_no_delay: bool) -> io::Result<Self> {
        let tcp_listener = TcpListener::bind(addr).await?;
        let udp_socket = UdpSocket::bind(addr).await?;
        Ok(Self {
            tcp_listener,
            udp_socket: Arc::new(udp_socket),
            tcp_no_delay,
        })
    }

    pub async fn run(&self, handler: Arc<dyn Handler + Send + Sync>) -> io::Result<()> {
        let h = handler.clone();
        let datagram = self.udp_socket.clone();
        tokio::spawn(async move {
            let _ = h.handle_datagram(&*datagram).await;
        });

        loop {
            let (mut stream, _) = self.tcp_listener.accept().await?;
            if self.tcp_no_delay {
                if let Err(e) = stream.set_nodelay(true) {
                    error!("set nodelay failed: {}", e);
                }
            }
            let h = handler.clone();
            tokio::spawn(async move {
                let _ = h.handle_stream(&mut stream).await;
            });
        }
    }
}
