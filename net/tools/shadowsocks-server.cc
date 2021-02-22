#include <stdint.h>

#include "base/flags.h"
#include "base/logging.h"
#include "net/asio.h"
#include "net/asio-flags.h"
#include "net/shadowsocks/aes-crypto.h"
#include "net/shadowsocks/tcp-server.h"

DEFINE_FLAG(net::address, ip, net::address_v4::loopback(), "");
DEFINE_FLAG(uint16_t, port, 8388, "");
DEFINE_FLAG(std::string, password, "", "");

int main(int argc, char *argv[]) {
    base::init_logging();
    base::parse_flags(argc, argv);

    net::io_context io_context;
    net::shadowsocks::TcpServer tcp_server(
        io_context.get_executor(),
        net::tcp::endpoint(flags::ip, flags::port),
        // TODO(iceboy): Support other encryption algorithms.
        net::shadowsocks::AesMasterKey::from_password(flags::password));
    io_context.run();
}
