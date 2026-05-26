use std::{io, net::SocketAddr, sync::Arc};

use log::error;
use serde::Deserialize;
use tokio::task::JoinSet;

use crate::{
    listener::Listener,
    registry::{ConnectorConfig, HandlerConfig, Registry, REGISTRY},
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
    config: Arc<Config>,
    handlers: Vec<(SocketAddr, Arc<dyn Handler + Send + Sync>)>,
    connectors: Vec<(String, Arc<dyn Connector>)>,
}

impl Proxy {
    pub fn new(config: Config) -> Self {
        Self {
            config: Arc::new(config),
            handlers: Vec::new(),
            connectors: Vec::new(),
        }
    }

    // TODO: Create objects iteratively.
    pub fn load(&mut self) {
        let c = self.config.clone();
        let registry = REGISTRY.lock().unwrap();
        for connector_config in &c.connectors {
            if let Err(e) = self.get_connector(&connector_config.name, &registry) {
                error!("get connector failed: {}", e);
            }
        }

        // TODO: skip creating handlers if in TCP connect mode
        for handler_config in &c.handlers {
            match registry.create_handler(self, handler_config) {
                Ok(handler) => {
                    self.handlers.push((handler_config.listen, handler));
                }
                Err(e) => error!("create handler failed: {}", e),
            }
        }
    }

    pub async fn run(&self) -> io::Result<()> {
        let mut set = JoinSet::new();
        for (listen, handler) in &self.handlers {
            let listener = Listener::bind(listen).await?;
            let h = handler.clone();
            set.spawn(async move { listener.run(h).await });
        }
        set.join_all().await;
        Ok(())
    }

    fn get_connector(&mut self, name: &str, registry: &Registry) -> io::Result<Arc<dyn Connector>> {
        if let Some((_, connector)) = self.connectors.iter().find(|(n, _)| n == name) {
            return Ok(connector.clone());
        }
        let config = match self.config.connectors.iter().find(|c| c.name == name) {
            Some(c) => c.clone(),
            None => {
                return Err(io::Error::new(
                    io::ErrorKind::NotFound,
                    "connector not found",
                ));
            }
        };
        match registry.create_connector(self, &config) {
            Ok(connector) => {
                self.connectors.push((name.to_string(), connector.clone()));
                Ok(connector)
            }
            Err(e) => Err(e),
        }
    }
}
