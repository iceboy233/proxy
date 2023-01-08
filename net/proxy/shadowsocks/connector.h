#ifndef _NET_PROXY_SHADOWSOCKS_CONNECTOR_H
#define _NET_PROXY_SHADOWSOCKS_CONNECTOR_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "absl/random/random.h"
#include "net/endpoint.h"
#include "net/proxy/connector.h"
#include "net/proxy/shadowsocks/method.h"
#include "net/proxy/shadowsocks/pre-shared-key.h"
#include "net/proxy/shadowsocks/salt-filter.h"

namespace net {
namespace proxy {
namespace shadowsocks {

class Connector : public proxy::Connector {
public:
    Connector(
        const any_io_executor &executor,
        proxy::Connector &base_connector);

    Connector(const Connector &) = delete;
    Connector &operator=(const Connector &) = delete;

    struct InitOptions {
        std::vector<Endpoint> endpoints;
        const Method *method = &Method::aes_128_gcm();
        std::string password;
        size_t min_padding_length = 1;
        size_t max_padding_length = 900;
    };

    bool init(const InitOptions &options);

    void connect_tcp_v4(
        const address_v4 &address,
        uint16_t port,
        const_buffer initial_data,
        absl::AnyInvocable<void(
            std::error_code, std::unique_ptr<Stream>) &&> callback) override;

    void connect_tcp_v6(
        const address_v6 &address,
        uint16_t port,
        const_buffer initial_data,
        absl::AnyInvocable<void(
            std::error_code, std::unique_ptr<Stream>) &&> callback) override;

    void connect_tcp_host(
        std::string_view host,
        uint16_t port,
        const_buffer initial_data,
        absl::AnyInvocable<void(
            std::error_code, std::unique_ptr<Stream>) &&> callback) override;

    std::error_code bind_udp_v4(std::unique_ptr<Datagram> &datagram) override;
    std::error_code bind_udp_v6(std::unique_ptr<Datagram> &datagram) override;

private:
    class TcpStream;

    any_io_executor executor_;
    proxy::Connector &base_connector_;
    std::vector<Endpoint> endpoints_;
    std::vector<Endpoint>::iterator endpoints_iter_;
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
