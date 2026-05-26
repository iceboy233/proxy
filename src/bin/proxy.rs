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

fn main() -> Result<(), Box<dyn Error>> {
    simple_logger::init_with_env()?;
    let options = options().run();
    configs::init();
    let config: Config = toml::from_str(&fs::read_to_string(&options.config)?)?;
    let mut proxy = Proxy::new(config);
    proxy.load();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(proxy.run())?;
    Ok(())
}
