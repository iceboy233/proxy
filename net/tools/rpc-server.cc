#include "base/flags.h"
#include "net/asio.h"
#include "net/asio-flags.h"
#include "net/rpc/server.h"

DEFINE_FLAG(net::address, ip, net::address_v4::loopback(), "");
DEFINE_FLAG(uint16_t, port, 1024, "");

int main(int argc, char *argv[]) {
    using namespace net;

    base::parse_flags(argc, argv);

    io_context io_context;
    rpc::Server server(io_context.get_executor(), {flags::ip, flags::port}, {});
    server.start();
    io_context.run();
}
