mod echo;
mod socks;
mod system;

pub fn init() {
    echo::init();
    socks::init();
    system::init();
}
