#include <cstdint>

#include "base/flags.h"
#include "base/logging.h"
#include "net/asio.h"
#include "net/asio-flags.h"
#include "net/socks/tcp-server.h"

DEFINE_FLAG(net::address, ip, net::address_v4::loopback(), "");
DEFINE_FLAG(uint16_t, port, 1080, "");

int main(int argc, char *argv[]) {
    using namespace net::socks;

    base::init_logging();
    base::parse_flags(argc, argv);

    boost::asio::io_context io_context;
    auto executor = io_context.get_executor();
    TcpServer tcp_server(
        executor, net::tcp::endpoint(flags::ip, flags::port), {});
    io_context.run();
}
