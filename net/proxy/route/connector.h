#ifndef _NET_PROXY_ROUTE_CONNECTOR_H
#define _NET_PROXY_ROUTE_CONNECTOR_H

#include <vector>

#include "net/proxy/connector.h"
#include "net/proxy/route/host-matcher.h"

namespace net {
namespace proxy {
namespace route {

class Connector : public proxy::Connector {
public:
    struct Rule {
        std::vector<std::string> hosts;
        std::vector<std::string> host_suffixes;
        bool is_default = false;
        proxy::Connector *connector = nullptr;
    };

    explicit Connector(absl::Span<Rule const> rules);

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

    std::error_code bind_udp_v4(
        std::unique_ptr<Datagram> &datagram) override;

    std::error_code bind_udp_v6(
        std::unique_ptr<Datagram> &datagram) override;

private:
    HostMatcher host_matcher_;
    std::vector<proxy::Connector *> connectors_;
    proxy::Connector *default_connector_ = nullptr;
};

}  // namespace route
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_ROUTE_CONNECTOR_H
