use std::{io, sync::Arc};

use serde::Deserialize;

use crate::{
    connectors::shadowsocks::ShadowsocksConnector,
    handlers::shadowsocks::ShadowsocksHandler,
    protocols::shadowsocks::{MasterKey, Method},
    registry::Registry,
};

#[derive(Clone, Debug, Deserialize)]
pub struct ShadowsocksHandlerConfig {
    pub method: Method,
    pub password: String,

    #[serde(default)]
    pub connector: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct ShadowsocksConnectorConfig {
    pub server: String,
    pub method: Method,
    pub password: String,

    #[serde(default)]
    pub connector: String,

    #[serde(default = "default_min_padding_len")]
    pub min_padding_len: u16,

    #[serde(default = "default_max_padding_len")]
    pub max_padding_len: u16,
}

fn default_min_padding_len() -> u16 {
    1
}

fn default_max_padding_len() -> u16 {
    900
}

pub fn init(registry: &mut Registry) {
    registry.register_handler("shadowsocks", |get_connector, config| {
        let c: ShadowsocksHandlerConfig = config
            .params
            .try_into()
            .map_err(|e| io::Error::other(format!("invalid shadowsocks handler config: {}", e)))?;

        let connector = get_connector(&c.connector)?;
        let master_key = MasterKey::new(c.method, &c.password)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid password"))?;

        Ok(Arc::new(ShadowsocksHandler::new(
            connector, c.method, master_key,
        )))
    });

    registry.register_connector("shadowsocks", |get_connector, config| {
        let c: ShadowsocksConnectorConfig = config.params.try_into().map_err(|e| {
            io::Error::other(format!("invalid shadowsocks connector config: {}", e))
        })?;

        let connector = get_connector(&c.connector)?;
        let server = c
            .server
            .parse()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid server"))?;
        let master_key = MasterKey::new(c.method, &c.password)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid password"))?;

        Ok(Arc::new(ShadowsocksConnector::new(
            connector,
            server,
            c.method,
            master_key,
            c.min_padding_len,
            c.max_padding_len,
        )))
    });
}
