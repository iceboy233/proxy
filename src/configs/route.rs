use std::{io, sync::Arc};

use ip_network::IpNetwork;
use serde::Deserialize;

use crate::{connectors::route::RouteConnectorBuilder, registry::Registry};

#[derive(Clone, Debug, Deserialize)]
pub struct RouteConnectorConfig {
    #[serde(default)]
    rules: Vec<RouteConnectorRuleConfig>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RouteConnectorRuleConfig {
    #[serde(default)]
    networks: Vec<IpNetwork>,

    #[serde(default)]
    hosts: Vec<String>,

    #[serde(default)]
    host_suffixes: Vec<String>,

    #[serde(default)]
    default: bool,

    #[serde(default)]
    drop: bool,

    #[serde(default)]
    connector: String,
}

pub fn init(registry: &mut Registry) {
    registry.register_connector("route", |get_connector, config| {
        let c: RouteConnectorConfig = config
            .params
            .try_into()
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid connector config"))?;
        let mut builder = RouteConnectorBuilder::new();
        for rule in &c.rules {
            let connector = if rule.drop {
                None
            } else {
                Some(get_connector(&rule.connector)?)
            };
            if rule.default {
                builder.set_default_connector(connector.clone());
            }
            builder.add_rule(&rule.networks, &rule.hosts, &rule.host_suffixes, connector);
        }
        Ok(Arc::new(builder.build()))
    });
}
