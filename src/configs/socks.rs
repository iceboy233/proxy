use std::{io, sync::Arc};

use serde::Deserialize;

use crate::{connectors::socks::SocksConnector, handlers::socks::SocksHandler, registry::REGISTRY};

#[derive(Clone, Debug, Deserialize)]
pub struct SocksHandlerConfig {
    #[serde(default)]
    pub connector: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct SocksConnectorConfig {
    pub server: String,

    #[serde(default)]
    pub connector: String,
}

pub fn init() {
    let mut registry = REGISTRY.lock().unwrap();

    registry.register_handler("socks", |get_connector, config| {
        let c: SocksHandlerConfig = config
            .params
            .try_into()
            .map_err(|e| io::Error::other(format!("invalid socks handler config: {}", e)))?;

        let connector = get_connector(&c.connector)?;

        Ok(Arc::new(SocksHandler::new(connector)))
    });

    registry.register_connector("socks", |get_connector, config| {
        let c: SocksConnectorConfig = config
            .params
            .try_into()
            .map_err(|e| io::Error::other(format!("invalid socks connector config: {}", e)))?;

        let connector = get_connector(&c.connector)?;

        let server = c
            .server
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid server"))?;
        Ok(Arc::new(SocksConnector::new(connector, server)))
    });
}
