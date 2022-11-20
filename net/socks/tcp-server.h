#ifndef _NET_SOCKS_TCP_SERVER_H
#define _NET_SOCKS_TCP_SERVER_H

#include <chrono>
#include <cstdint>
#include <optional>

#include "net/asio.h"
#include "net/proxy/connector.h"
#include "net/rate-limiter.h"

namespace net {
namespace socks {

class TcpServer {
public:
    struct Options {
        uint64_t forward_bytes_rate_limit = 0;
        uint64_t backward_bytes_rate_limit = 0;
        std::chrono::nanoseconds rate_limit_capacity =
            std::chrono::milliseconds(125);
    };

    TcpServer(
        const any_io_executor &executor,
        const tcp::endpoint &endpoint,
        Connector &connector,
        const Options &options);

    void accept();

private:
    class Connection;

    any_io_executor executor_;
    tcp::acceptor acceptor_;
    Connector &connector_;
    std::optional<RateLimiter> forward_bytes_rate_limiter_;
    std::optional<RateLimiter> backward_bytes_rate_limiter_;
};

}  // namespace socks
}  // namespace net

#endif  // _NET_SOCKS_TCP_SERVER_H
