#ifndef _NET_SHADOWSOCKS_UDP_SERVER_H
#define _NET_SHADOWSOCKS_UDP_SERVER_H

#include <chrono>
#include <cstdint>
#include <tuple>

#include "absl/container/flat_hash_map.h"
#include "absl/types/span.h"
#include "net/asio.h"
#include "net/asio-hash.h"
#include "net/rate-limiter.h"
#include "net/shadowsocks/encryption.h"
#include "net/timer-list.h"

namespace net {
namespace shadowsocks {

// The provided executor must be single-threaded, and all functions must be
// called in the executor thread.
class UdpServer {
public:
    struct Options {
        SaltFilter *salt_filter = nullptr;
        std::chrono::nanoseconds connection_timeout =
            std::chrono::nanoseconds::zero();
        uint64_t forward_packets_rate_limit = 0;
        uint64_t backward_packets_rate_limit = 0;
        std::chrono::nanoseconds rate_limit_capacity =
            std::chrono::milliseconds(125);
    };

    UdpServer(
        const any_io_executor &executor,
        const udp::endpoint &endpoint,
        const MasterKey &master_key,
        const Options &options);

private:
    class Connection;

    void forward_receive();
    void forward_parse(absl::Span<const uint8_t> chunk);
    void forward_dispatch(
        absl::Span<const uint8_t> chunk,
        const udp::endpoint &server_endpoint);

    any_io_executor executor_;
    SaltFilter *salt_filter_;
    std::chrono::nanoseconds connection_timeout_;
    udp::socket socket_;
    EncryptedDatagram encrypted_datagram_;
    TimerList timer_list_;
    absl::flat_hash_map<std::tuple<udp::endpoint, bool>, Connection *>
        connections_;
    udp::endpoint receive_endpoint_;
    std::optional<RateLimiter> forward_packets_rate_limiter_;
    std::optional<RateLimiter> backward_packets_rate_limiter_;
};

}  // namespace shadowsocks
}  // namespace net

#endif  // _NET_SHADOWSOCKS_UDP_SERVER_H
