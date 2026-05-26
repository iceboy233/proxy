use bpaf::Bpaf;
use proxy::{
    configs,
    proxy::{Config, Proxy},
};
use std::{error::Error, fs};

#[derive(Clone, Debug, Bpaf)]
#[bpaf(options, version)]
struct Options {
    #[bpaf(short, long)]
    /// Config file path.
    config: String,
    // TODO: tcp_connect_target
    // TODO: tcp_connect_with
}

// TODO: create runtime separately
#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn Error>> {
    let options = options().run();
    configs::init();
    let config: Config = toml::from_str(&fs::read_to_string(&options.config)?)?;
    let mut proxy = Proxy::new(config);
    proxy.load();
    proxy.run().await?;
    Ok(())
}
