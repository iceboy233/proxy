use bpaf::Bpaf;
use proxy::{handlers::echo::EchoHandler, listener::Listener};
use std::{io, net::SocketAddr, sync::Arc};

#[derive(Clone, Debug, Bpaf)]
#[bpaf(options, version)]
struct Options {
    #[bpaf(short, long)]
    listen: SocketAddr,
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> io::Result<()> {
    let options = options().run();
    let listener = Listener::bind(&options.listen).await?;
    listener.run(Arc::new(EchoHandler)).await
}
