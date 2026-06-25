use std::sync::Arc;

use crate::{handlers::echo::EchoHandler, registry::Registry};

pub fn init(registry: &mut Registry) {
    registry.register_handler("echo", |_, _| Ok(Arc::new(EchoHandler)));
}
