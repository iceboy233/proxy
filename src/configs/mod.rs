use crate::registry::Registry;

mod echo;
mod route;
mod shadowsocks;
mod socks;
mod system;

pub fn init(registry: &mut Registry) {
    echo::init(registry);
    route::init(registry);
    shadowsocks::init(registry);
    socks::init(registry);
    system::init(registry);
}
