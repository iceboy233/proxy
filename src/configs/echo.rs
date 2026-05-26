use std::sync::Arc;

use crate::{handlers::echo::EchoHandler, registry::REGISTRY};

pub fn init() {
    let mut registry = REGISTRY.lock().unwrap();
    registry.register_handler("echo", |_, _| Ok(Arc::new(EchoHandler)));
}
