use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{Arc, LazyLock, Mutex},
};

use serde::Deserialize;

use crate::{
    proxy::Proxy,
    traits::{Connector, Handler},
};

#[derive(Clone, Debug, Deserialize)]
pub struct HandlerConfig {
    pub name: String,
    pub listen: SocketAddr,
    pub r#type: String,

    #[serde(flatten)]
    pub params: toml::Table,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ConnectorConfig {
    pub name: String,
    pub r#type: String,

    #[serde(flatten)]
    pub params: toml::Table,
}

pub struct Registry {
    handlers: HashMap<String, CreateHandlerFunc>,
    connectors: HashMap<String, CreateConnectorFunc>,
}

pub type CreateHandlerFunc = fn(&mut Proxy, &HandlerConfig) -> io::Result<Arc<dyn Handler + Send + Sync>>;
pub type CreateConnectorFunc = fn(&mut Proxy, &ConnectorConfig) -> io::Result<Arc<dyn Connector + Send + Sync>>;

impl Registry {
    pub fn register_handler(&mut self, r#type: &str, func: CreateHandlerFunc) {
        if self.handlers.contains_key(r#type) {
            log::error!("duplicate handler type: {}", r#type);
            return;
        }
        self.handlers.insert(r#type.to_string(), func);
    }

    pub fn register_connector(&mut self, r#type: &str, func: CreateConnectorFunc) {
        if self.connectors.contains_key(r#type) {
            log::error!("duplicate connector type: {}", r#type);
            return;
        }
        self.connectors.insert(r#type.to_string(), func);
    }

    pub fn create_handler(
        &self,
        proxy: &mut Proxy,
        config: &HandlerConfig,
    ) -> io::Result<Arc<dyn Handler + Send + Sync>> {
        if let Some(func) = self.handlers.get(&config.r#type) {
            func(proxy, config)
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "invalid handler type",
            ))
        }
    }

    pub fn create_connector(
        &self,
        proxy: &mut Proxy,
        config: &ConnectorConfig,
    ) -> io::Result<Arc<dyn Connector + Send + Sync>> {
        if let Some(func) = self.connectors.get(&config.r#type) {
            func(proxy, config)
        } else {
            Err(io::Error::new(
                io::ErrorKind::NotFound,
                "invalid connector type",
            ))
        }
    }
}

pub static REGISTRY: LazyLock<Mutex<Registry>> = LazyLock::new(|| {
    let registry = Registry {
        handlers: HashMap::new(),
        connectors: HashMap::new(),
    };
    Mutex::new(registry)
});
