#ifndef _NET_PROXY_SHADOWSOCKS_CONNECTOR_H
#define _NET_PROXY_SHADOWSOCKS_CONNECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "absl/random/random.h"
#include "net/interface/connector.h"
#include "net/proxy/shadowsocks/method.h"
#include "net/proxy/shadowsocks/pre-shared-key.h"
#include "net/proxy/shadowsocks/salt-filter.h"
#include "net/types/addr-port.h"

namespace net {
namespace proxy {
namespace shadowsocks {

class Connector : public net::Connector {
public:
    explicit Connector(net::Connector &base_connector)
        : base_connector_(base_connector) {}

    Connector(const Connector &) = delete;
    Connector &operator=(const Connector &) = delete;

    struct InitOptions {
        std::vector<AddrPort> servers;
        const Method *method = &Method::aes_128_gcm();
        std::string password;
        size_t min_padding_length = 1;
        size_t max_padding_length = 900;
    };

    bool init(const InitOptions &options);

    void connect(
        const HostPort &target,
        const_buffer initial_data,
        absl::AnyInvocable<void(
            std::error_code, std::unique_ptr<Stream>) &&> callback) override;

    std::error_code bind(
        const udp::endpoint &endpoint,
        std::unique_ptr<Datagram> &datagram) override;

private:
    class TcpStream;

    net::Connector &base_connector_;
    std::vector<AddrPort> servers_;
    std::vector<AddrPort>::iterator servers_iter_;
    PreSharedKey pre_shared_key_;
    size_t min_padding_length_;
    size_t max_padding_length_;
    SaltFilter salt_filter_;
    absl::BitGen bit_gen_;
};

}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_SHADOWSOCKS_CONNECTOR_H
