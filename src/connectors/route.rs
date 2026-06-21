use std::{io, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use fst::raw::Fst;

use crate::traits::{AsyncDatagram, AsyncStream, Connector, DatagramConnector, StreamConnector};

pub struct RouteConnector {
    host_matcher: HostMatcher,
    connectors: Box<[Option<Arc<dyn Connector + Send + Sync>>]>,
    default_connector: Option<Arc<dyn Connector + Send + Sync>>,
}

pub struct RouteConnectorBuilder {
    host_matcher: HostMatcherBuilder,
    connectors: Vec<Option<Arc<dyn Connector + Send + Sync>>>,
    default_connector: Option<Arc<dyn Connector + Send + Sync>>,
}

impl RouteConnectorBuilder {
    pub fn new() -> Self {
        Self {
            host_matcher: HostMatcherBuilder::new(),
            connectors: Vec::new(),
            default_connector: None,
        }
    }

    pub fn add_rule<H, S>(
        &mut self,
        hosts: H,
        host_suffixes: S,
        connector: Option<Arc<dyn Connector + Send + Sync>>,
    ) where
        H: IntoIterator,
        H::Item: AsRef<str>,
        S: IntoIterator,
        S::Item: AsRef<str>,
    {
        self.connectors.push(connector);
        let idx = (self.connectors.len() - 1) as u64;
        for host in hosts {
            self.host_matcher.add(host.as_ref(), idx);
        }
        for host_suffix in host_suffixes {
            self.host_matcher.add_suffix(host_suffix.as_ref(), idx);
        }
    }

    pub fn set_default_connector(&mut self, connector: Option<Arc<dyn Connector + Send + Sync>>) {
        self.default_connector = connector;
    }

    pub fn build(self) -> RouteConnector {
        RouteConnector {
            host_matcher: self.host_matcher.build(),
            connectors: self.connectors.into_boxed_slice(),
            default_connector: self.default_connector,
        }
    }
}

struct HostMatcher {
    fst: Fst<Vec<u8>>,
}

impl HostMatcher {
    fn matches(&self, host: &str) -> Option<u64> {
        let mut node = self.fst.root();
        let mut out = fst::raw::Output::zero();
        let mut last = None;
        let mut partial = false;

        for &b in host.as_bytes().iter().rev() {
            if let Some(idx) = node.find_input(b) {
                let t = node.transition(idx);
                out = out.cat(t.out);
                node = self.fst.node(t.addr);
            } else {
                partial = true;
                break;
            }
            if b == b'.' && node.is_final() {
                last = Some(out.cat(node.final_output()));
            }
        }
        if !partial && node.is_final() {
            last = Some(out.cat(node.final_output()));
        }

        last.map(|o| o.value())
    }
}

struct HostMatcherBuilder {
    entries: Vec<(String, u64)>,
}

impl HostMatcherBuilder {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    fn add(&mut self, host: &str, value: u64) {
        let rev: String = host.chars().rev().collect();
        self.entries.push((rev, value));
    }

    fn add_suffix(&mut self, host: &str, value: u64) {
        let mut rev: String = host.chars().rev().collect();
        self.entries.push((rev.clone(), value));
        rev.push('.');
        self.entries.push((rev, value));
    }

    fn build(mut self) -> HostMatcher {
        self.entries.sort_by(|a, b| a.0.cmp(&b.0));
        let fst = Fst::from_iter_map(self.entries).unwrap();
        HostMatcher { fst }
    }
}

#[async_trait]
impl StreamConnector for RouteConnector {
    async fn connect(
        &self,
        endpoint: SocketAddr,
        initial_data: &[u8],
    ) -> io::Result<Box<dyn AsyncStream + Send + Sync + Unpin>> {
        match &self.default_connector {
            Some(c) => c.connect(endpoint, initial_data).await,
            None => Err(io::ErrorKind::NetworkUnreachable.into()),
        }
    }

    async fn connect_host(
        &self,
        host: &str,
        port: u16,
        initial_data: &[u8],
    ) -> io::Result<Box<dyn AsyncStream + Send + Sync + Unpin>> {
        let connector = self
            .host_matcher
            .matches(host)
            .and_then(|idx| self.connectors[idx as usize].as_ref())
            .or(self.default_connector.as_ref())
            .map(|c| c.as_ref());
        match connector {
            Some(c) => c.connect_host(host, port, initial_data).await,
            None => Err(io::ErrorKind::NetworkUnreachable.into()),
        }
    }
}

#[async_trait]
impl DatagramConnector for RouteConnector {
    async fn bind(
        &self,
        _endpoint: SocketAddr,
    ) -> io::Result<Box<dyn AsyncDatagram + Send + Sync + Unpin>> {
        Err(io::Error::other("datagram is not supported yet"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_host_matcher() {
        let mut builder = HostMatcherBuilder::new();
        builder.add("hana.co", 100);
        builder.add_suffix("nana.co", 200);
        let matcher = builder.build();
        assert_eq!(matcher.matches(""), None);
        assert_eq!(matcher.matches("ana.co"), None);
        assert_eq!(matcher.matches("hana.c"), None);
        assert_eq!(matcher.matches("hana.co"), Some(100));
        assert_eq!(matcher.matches("hana.com"), None);
        assert_eq!(matcher.matches("hana.co."), None);
        assert_eq!(matcher.matches(".hana.co"), None);
        assert_eq!(matcher.matches("ba.hana.co"), None);
        assert_eq!(matcher.matches("bahana.co"), None);
        assert_eq!(matcher.matches("nana.co"), Some(200));
        assert_eq!(matcher.matches(".nana.co"), Some(200));
        assert_eq!(matcher.matches("ba.nana.co"), Some(200));
        assert_eq!(matcher.matches("ba..nana.co"), Some(200));
        assert_eq!(matcher.matches("banana.co"), None);
    }
}
