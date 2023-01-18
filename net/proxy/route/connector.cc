#include "net/proxy/route/connector.h"

#include <cstdlib>

namespace net {
namespace proxy {
namespace route {

Connector::Connector(absl::Span<Rule const> rules) {
    for (const Rule &rule : rules) {
        connectors_.push_back(rule.connector);
        for (const std::string &host : rule.hosts) {
            host_matcher_.add(host, connectors_.size() - 1);
        }
        for (const std::string &host_suffix : rule.host_suffixes) {
            host_matcher_.add_suffix(host_suffix, connectors_.size() - 1);
        }
        if (rule.is_default && !default_connector_) {
            default_connector_ = rule.connector;
        }
    }
    host_matcher_.build();
}

void Connector::connect_tcp_v4(
    const address_v4 &address,
    uint16_t port,
    const_buffer initial_data,
    absl::AnyInvocable<void(
        std::error_code, std::unique_ptr<Stream>) &&> callback) {
    // TODO
    auto *connector = default_connector_;
    if (!connector) {
        std::move(callback)(
            make_error_code(std::errc::network_unreachable), nullptr);
        return;
    }
    connector->connect_tcp_v4(address, port, initial_data, std::move(callback));
}

void Connector::connect_tcp_v6(
    const address_v6 &address,
    uint16_t port,
    const_buffer initial_data,
    absl::AnyInvocable<void(
        std::error_code, std::unique_ptr<Stream>) &&> callback) {
    // TODO
    auto *connector = default_connector_;
    if (!connector) {
        std::move(callback)(
            make_error_code(std::errc::network_unreachable), nullptr);
        return;
    }
    connector->connect_tcp_v6(address, port, initial_data, std::move(callback));
}

void Connector::connect_tcp_host(
    std::string_view host,
    uint16_t port,
    const_buffer initial_data,
    absl::AnyInvocable<void(
        std::error_code, std::unique_ptr<Stream>) &&> callback) {
    std::optional<int> index = host_matcher_.match(host);
    auto *connector = index ? connectors_[*index] : default_connector_;
    if (!connector) {
        std::move(callback)(
            make_error_code(std::errc::network_unreachable), nullptr);
        return;
    }
    connector->connect_tcp_host(host, port, initial_data, std::move(callback));
}

std::error_code Connector::bind_udp_v4(std::unique_ptr<Datagram> &datagram) {
    // TODO
    return make_error_code(std::errc::operation_not_supported);
}

std::error_code Connector::bind_udp_v6(std::unique_ptr<Datagram> &datagram) {
    // TODO
    return make_error_code(std::errc::operation_not_supported);
}

}  // namespace route
}  // namespace proxy
}  // namespace net
