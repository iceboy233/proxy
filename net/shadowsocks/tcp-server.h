#ifndef _NET_SHADOWSOCKS_TCP_SERVER_H
#define _NET_SHADOWSOCKS_TCP_SERVER_H

#include <chrono>
#include <cstdint>

#include "net/asio.h"
#include "net/rate-limiter.h"
#include "net/proxy/connector.h"
#include "net/shadowsocks/encryption.h"
#include "net/timer-list.h"

namespace net {
namespace shadowsocks {

// The provided executor must be single-threaded, and all functions must be
// called in the executor thread.
class TcpServer {
public:
    struct Options {
        SaltFilter *salt_filter = nullptr;
        std::chrono::nanoseconds connection_timeout =
            std::chrono::nanoseconds::zero();
        uint64_t forward_bytes_rate_limit = 0;
        uint64_t backward_bytes_rate_limit = 0;
        std::chrono::nanoseconds rate_limit_capacity =
            std::chrono::milliseconds(125);
    };

    TcpServer(
        const any_io_executor &executor,
        const tcp::endpoint &endpoint,
        const MasterKey &master_key,
        Connector &connector,
        const Options &options);

private:
    class Connection;

    void accept();

    any_io_executor executor_;
    const MasterKey &master_key_;
    SaltFilter *salt_filter_;
    std::chrono::nanoseconds connection_timeout_;
    tcp::acceptor acceptor_;
    Connector &connector_;
    TimerList timer_list_;
    std::optional<RateLimiter> forward_bytes_rate_limiter_;
    std::optional<RateLimiter> backward_bytes_rate_limiter_;
};

}  // namespace shadowsocks
}  // namespace net

#endif  // _NET_SHADOWSOCKS_TCP_SERVER_H
