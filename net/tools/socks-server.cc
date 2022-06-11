#include <cstdint>

#include "base/flags.h"
#include "base/logging.h"
#include "net/asio.h"
#include "net/endpoint.h"
#include "net/rate-limiter.h"
#include "net/socks/tcp-server.h"

DEFINE_FLAG(net::Endpoint, endpoint,
            net::Endpoint(net::address_v4::loopback(), 1080), "");
DEFINE_FLAG(uint64_t, tcp_forward_bytes_rate_limit, 0, "");
DEFINE_FLAG(uint64_t, tcp_backward_bytes_rate_limit, 0, "");

int main(int argc, char *argv[]) {
    using namespace net::socks;

    base::init_logging();
    base::parse_flags(argc, argv);

    boost::asio::io_context io_context;
    auto executor = io_context.get_executor();
    TcpServer::Options options;
    options.forward_bytes_rate_limit = flags::tcp_forward_bytes_rate_limit;
    options.backward_bytes_rate_limit = flags::tcp_backward_bytes_rate_limit;
    TcpServer tcp_server(executor, flags::endpoint, options);
    io_context.run();
}
