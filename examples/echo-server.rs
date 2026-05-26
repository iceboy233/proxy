use bpaf::Bpaf;
use proxy::{
    handlers::echo::EchoHandler,
    traits::{DatagramHandler, StreamHandler},
};
use std::{io, net::SocketAddr};
use tokio::net::{TcpListener, UdpSocket};

#[derive(Clone, Debug, Bpaf)]
#[bpaf(options, version)]
struct Options {
    #[bpaf(short, long)]
    listen: SocketAddr,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let options = options().run();
    let handler = EchoHandler;

    let tcp_listener = TcpListener::bind(options.listen).await?;
    let udp_socket = UdpSocket::bind(options.listen).await?;

    let h = handler.clone();
    tokio::spawn(async move {
        let _ = h.handle_datagram(Box::new(udp_socket)).await;
    });

    loop {
        let (stream, _) = tcp_listener.accept().await?;
        let h = handler.clone();
        tokio::spawn(async move {
            let _ = h.handle_stream(Box::new(stream)).await;
        });
    }
}
