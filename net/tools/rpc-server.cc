#include "base/flags.h"
#include "net/asio.h"
#include "net/endpoint.h"
#include "net/rpc/server.h"

DEFINE_FLAG(net::Endpoint, endpoint,
            net::Endpoint(net::address_v4::loopback(), 1024), "");

int main(int argc, char *argv[]) {
    using namespace net;

    base::parse_flags(argc, argv);

    io_context io_context;
    rpc::Server server(io_context.get_executor(), flags::endpoint, {});
    server.start();
    io_context.run();
}
