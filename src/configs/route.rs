use std::{
    fs::File,
    io::{self, BufRead},
    path::{Path, PathBuf},
    str::FromStr,
    sync::Arc,
};

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
    network_files: Vec<PathBuf>,

    #[serde(default)]
    hosts: Vec<String>,

    #[serde(default)]
    host_files: Vec<PathBuf>,

    #[serde(default)]
    host_suffixes: Vec<String>,

    #[serde(default)]
    host_suffix_files: Vec<PathBuf>,

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
            let mut networks = rule.networks.clone();
            for file in &rule.network_files {
                read_network_file(file, &mut networks)?;
            }
            let mut hosts = rule.hosts.clone();
            for file in &rule.host_files {
                read_host_file(file, &mut hosts)?;
            }
            let mut host_suffixes = rule.host_suffixes.clone();
            for file in &rule.host_suffix_files {
                read_host_file(file, &mut host_suffixes)?;
            }
            let connector = if rule.drop {
                None
            } else {
                Some(get_connector(&rule.connector)?)
            };
            if rule.default {
                builder.set_default_connector(connector.clone());
            }
            builder.add_rule(&networks, &hosts, &rule.host_suffixes, connector);
        }
        Ok(Arc::new(builder.build()))
    });
}

fn read_network_file(file: &Path, networks: &mut Vec<IpNetwork>) -> io::Result<()> {
    for line_result in io::BufReader::new(File::open(file)?).lines() {
        let line = line_result?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        networks.push(
            IpNetwork::from_str(line).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?,
        );
    }
    Ok(())
}

fn read_host_file(file: &Path, hosts: &mut Vec<String>) -> io::Result<()> {
    for line_result in io::BufReader::new(File::open(file)?).lines() {
        let line = line_result?;
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        hosts.push(line.to_string());
    }
    Ok(())
}
