use std::sync::Arc;

use crate::{
    connectors::{socks::SocksConnector, system::SystemConnector},
    handlers::socks::SocksHandler,
    registry::REGISTRY,
};

pub fn init() {
    let mut registry = REGISTRY.lock().unwrap();

    registry.register_handler("socks", |_, _| {
        // TODO: get connector from registry
        Ok(Arc::new(SocksHandler::new(Arc::new(SystemConnector::new(true)))))
    });

    registry.register_connector("socks", |_, _| {
        // TODO: get connector from registry
        let connector = Arc::new(SystemConnector::new(true));
        // TODO: get server from config
        let server = "127.0.0.1:1080".parse().unwrap();
        Ok(Arc::new(SocksConnector::new(connector, server)))
    });
}
