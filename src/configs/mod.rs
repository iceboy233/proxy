mod echo;
mod route;
mod shadowsocks;
mod socks;
mod system;

pub fn init() {
    echo::init();
    route::init();
    shadowsocks::init();
    socks::init();
    system::init();
}
