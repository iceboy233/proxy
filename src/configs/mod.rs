mod echo;
mod shadowsocks;
mod socks;
mod system;

pub fn init() {
    echo::init();
    shadowsocks::init();
    socks::init();
    system::init();
}
