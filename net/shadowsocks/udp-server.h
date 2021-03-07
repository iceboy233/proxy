#ifndef _NET_SHADOWSOCKS_UDP_SERVER_H
#define _NET_SHADOWSOCKS_UDP_SERVER_H

#include <chrono>
#include <cstdint>
#include <tuple>

#include "absl/container/flat_hash_map.h"
#include "absl/types/span.h"
#include "net/asio.h"
#include "net/asio-hash.h"
#include "net/shadowsocks/encryption.h"

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
    Options options_;
    udp::socket socket_;
    EncryptedDatagram encrypted_datagram_;
    absl::flat_hash_map<std::tuple<udp::endpoint, bool>, Connection *>
        connections_;
    udp::endpoint receive_endpoint_;
};

}  // namespace shadowsocks
}  // namespace net

#endif  // _NET_SHADOWSOCKS_UDP_SERVER_H
