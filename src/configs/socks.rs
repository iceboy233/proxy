use std::sync::Arc;

use crate::{
    connectors::system::SystemConnector, handlers::socks::SocksHandler, registry::REGISTRY,
};

pub fn init() {
    let mut registry = REGISTRY.lock().unwrap();
    registry.register_handler("socks", |_, _| {
        // TODO: get connector from registry
        Ok(Arc::new(SocksHandler::new(Arc::new(SystemConnector::new(true)))))
    });
}
