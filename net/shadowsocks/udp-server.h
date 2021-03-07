#ifndef _NET_SHADOWSOCKS_UDP_SERVER_H
#define _NET_SHADOWSOCKS_UDP_SERVER_H

#include <list>

#include "absl/container/flat_hash_map.h"
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
        std::chrono::nanoseconds connection_timeout =
            std::chrono::nanoseconds::zero();
    };

    UdpServer(
        const any_io_executor &executor,
        const udp::endpoint &endpoint,
        const MasterKey &master_key,
        SaltFilter &salt_filter,
        const Options &options);

private:
    class Connection;

    void receive();
    void send(
        absl::Span<const uint8_t> chunk, const udp::endpoint &endpoint,
        std::function<void(std::error_code)> callback);
    void forward_dispatch(
        absl::Span<const uint8_t> chunk, const udp::endpoint &client_endpoint);

    any_io_executor executor_;
    const MasterKey &master_key_;
    SaltFilter &salt_filter_;
    Options options_;
    udp::socket socket_;
    EncryptedDatagram encrypted_datagram_;
    absl::flat_hash_map<udp::endpoint, Connection *> client_endpoints_;
};


}  // namespace shadowsocks
}  // namespace net

#endif  // _NET_SHADOWSOCKS_UDP_SERVER_H
