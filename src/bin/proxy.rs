use bpaf::Bpaf;
use proxy::{
    configs,
    constants::STREAM_BUFFER_SIZE,
    proxy::{Config, Proxy},
    registry::REGISTRY,
    traits::Connector,
};
use std::{
    error::Error,
    fs, io,
    net::SocketAddr,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{copy_bidirectional_with_sizes, AsyncRead, AsyncWrite, ReadBuf};

#[derive(Clone, Debug, Bpaf)]
#[bpaf(options, version)]
struct Options {
    #[bpaf(short, long)]
    /// Config file path in TOML format.
    config: String,

    #[bpaf(long, fallback(String::new()))]
    /// If specified, connects to the specified target instead of running the handlers.
    tcp_connect_target: String,

    #[bpaf(long, fallback(String::new()))]
    /// Connector to use when connecting to the target.
    tcp_connect_with: String,
}

fn main() -> Result<(), Box<dyn Error>> {
    simple_logger::init_with_env()?;
    let options = options().run();
    configs::init();
    let config: Config = toml::from_str(&fs::read_to_string(&options.config)?)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let mut proxy = Proxy::new(config);
    if !options.tcp_connect_target.is_empty() {
        let connector =
            proxy.get_connector(&options.tcp_connect_with, &REGISTRY.lock().unwrap())?;
        runtime.block_on(tcp_connect(connector.as_ref(), &options.tcp_connect_target))
    } else {
        proxy.create_handlers();
        runtime.block_on(proxy.run()).map_err(|e| e.into())
    }
}

async fn tcp_connect(
    connector: &(dyn Connector + Send + Sync),
    target: &str,
) -> Result<(), Box<dyn Error>> {
    let mut stream = if let Ok(addr) = target.parse::<SocketAddr>() {
        connector.connect(addr, &[]).await
    } else {
        let mut parts = target.rsplitn(2, ':');
        let port = parts.next().unwrap().parse::<u16>()?;
        let host = parts.next().unwrap();
        connector.connect_host(host, port, &[]).await
    }?;
    let mut stdio = StandardIo::new();
    copy_bidirectional_with_sizes(
        &mut stdio,
        &mut stream,
        STREAM_BUFFER_SIZE,
        STREAM_BUFFER_SIZE,
    )
    .await?;
    Ok(())
}

struct StandardIo {
    stdin: tokio::io::Stdin,
    stdout: tokio::io::Stdout,
    closed: bool,
    read_waker: Option<std::task::Waker>,
}

impl StandardIo {
    fn new() -> Self {
        Self {
            stdin: tokio::io::stdin(),
            stdout: tokio::io::stdout(),
            closed: false,
            read_waker: None,
        }
    }
}

impl AsyncRead for StandardIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.closed {
            return Poll::Ready(Ok(()));
        }
        self.read_waker = Some(cx.waker().clone());
        Pin::new(&mut self.stdin).poll_read(cx, buf)
    }
}

impl AsyncWrite for StandardIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stdout).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stdout).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.closed = true;
        if let Some(waker) = self.read_waker.take() {
            waker.wake();
        }
        Pin::new(&mut self.stdout).poll_shutdown(cx)
    }
}
