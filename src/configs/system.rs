use std::{io, sync::Arc};

use serde::Deserialize;

use crate::{connectors::system::SystemConnector, registry::REGISTRY};

#[derive(Clone, Debug, Deserialize)]
pub struct SystemConnectorConfig {
    #[serde(default = "default_true")]
    pub tcp_no_delay: bool,
}

fn default_true() -> bool {
    true
}

pub fn init() {
    let mut registry = REGISTRY.lock().unwrap();

    registry.register_connector("system", |_, config| {
        let c: SystemConnectorConfig = config
            .params
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid connector config"))?;

        Ok(Arc::new(SystemConnector::new(c.tcp_no_delay)))
    });
}
