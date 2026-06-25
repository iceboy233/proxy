use std::{io, net::SocketAddr, sync::Arc};

use log::error;
use serde::Deserialize;
use tokio::task::JoinSet;

use crate::{
    listener::Listener,
    registry::{ConnectorConfig, HandlerConfig, Registry},
    traits::{Connector, Handler},
};

#[derive(Clone, Debug, Deserialize)]
pub struct Config {
    #[serde(default)]
    handlers: Vec<HandlerConfig>,

    #[serde(default)]
    connectors: Vec<ConnectorConfig>,
}

pub struct Proxy {
    config: Config,
    handlers: Vec<(SocketAddr, bool, Arc<dyn Handler + Send + Sync>)>,
    connectors: Vec<(String, Arc<dyn Connector + Send + Sync>)>,
}

impl Proxy {
    pub fn new(mut config: Config) -> Self {
        // Add the default unnamed system connector if it doesn't exist.
        if !config.connectors.iter().any(|x| x.name == "") {
            config.connectors.push(ConnectorConfig {
                name: "".to_string(),
                r#type: "system".to_string(),
                params: toml::Table::new(),
            });
        }

        Self {
            config,
            handlers: Vec::new(),
            connectors: Vec::new(),
        }
    }

    pub fn create_handlers(&mut self, registry: &mut Registry) {
        let c = self.config.clone();
        for handler_config in c.handlers {
            let listen = handler_config.listen;
            let tcp_no_delay = handler_config.tcp_no_delay;
            match registry.create_handler(self, handler_config) {
                Ok(handler) => {
                    self.handlers.push((listen, tcp_no_delay, handler));
                }
                Err(e) => error!("create handler failed: {}", e),
            }
        }
    }

    pub async fn run(&self) -> io::Result<()> {
        let mut set = JoinSet::new();
        for (listen, tcp_no_delay, handler) in &self.handlers {
            let listener = Listener::bind(*listen, *tcp_no_delay).await?;
            let h = handler.clone();
            set.spawn(async move { listener.run(h).await });
        }
        set.join_all().await;
        Ok(())
    }

    pub fn get_connector(
        &mut self,
        name: &str,
        registry: &Registry,
    ) -> io::Result<Arc<dyn Connector + Send + Sync>> {
        if let Some((_, connector)) = self.connectors.iter().find(|(n, _)| n == name) {
            return Ok(connector.clone());
        }
        let Some(config) = self.config.connectors.iter().find(|c| c.name == name) else {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "connector not found",
            ));
        };
        let connector = registry.create_connector(self, config.clone())?;
        self.connectors.push((name.to_string(), connector.clone()));
        Ok(connector)
    }
}
