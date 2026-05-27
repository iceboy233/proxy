mod echo;
mod socks;

pub fn init() {
    echo::init();
    socks::init();
}
