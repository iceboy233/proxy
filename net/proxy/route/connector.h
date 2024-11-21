#ifndef _NET_PROXY_ROUTE_CONNECTOR_H
#define _NET_PROXY_ROUTE_CONNECTOR_H

#include <vector>

#include "net/interface/connector.h"
#include "net/proxy/route/host-matcher.h"

namespace net {
namespace proxy {
namespace route {

class Connector : public net::Connector {
public:
    struct Rule {
        std::vector<std::string> hosts;
        std::vector<std::string> host_suffixes;
        bool is_default = false;
        net::Connector *connector = nullptr;
    };

    explicit Connector(absl::Span<Rule const> rules);

    void connect(
        const tcp::endpoint &endpoint,
        const_buffer initial_data,
        absl::AnyInvocable<void(
            std::error_code, std::unique_ptr<Stream>) &&> callback) override;

    void connect(
        std::string_view host,
        uint16_t port,
        const_buffer initial_data,
        absl::AnyInvocable<void(
            std::error_code, std::unique_ptr<Stream>) &&> callback) override;

    std::error_code bind(
        const udp::endpoint &endpoint,
        std::unique_ptr<Datagram> &datagram) override;

private:
    HostMatcher host_matcher_;
    std::vector<net::Connector *> connectors_;
    net::Connector *default_connector_ = nullptr;
};

}  // namespace route
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_ROUTE_CONNECTOR_H
