#include <chrono>
#include <memory>
#include <string>
#include <vector>

#include "base/logging.h"
#include "net/proxy/ares/resolver.h"
#include "net/proxy/proxy.h"
#include "net/proxy/registry.h"
#include "net/proxy/system/connector.h"
#include "net/proxy/util/config.h"
#include "net/types/addr-port.h"

namespace net {
namespace proxy {

struct ResolverConfig {
    std::vector<std::string> server;
    std::string address_family = "prefer-v4";
};

template <>
struct ConfigVisitor<ResolverConfig> {
    template <typename V>
    void operator()(V &&v, ResolverConfig &c) const {
        v("server", c.server);
        v("address-family", c.address_family);
    }
};

struct SystemConnectorConfig {
    double timeout = 300;
    bool tcp_no_delay = true;
    int tcp_fast_open_connect = 1;
    ResolverConfig resolver;
};

template <>
struct ConfigVisitor<SystemConnectorConfig> {
    template <typename V>
    void operator()(V &&v, SystemConnectorConfig &c) const {
        v("timeout", c.timeout);
        v("tcp-no-delay", c.tcp_no_delay);
        v("tcp-fast-open-connect", c.tcp_fast_open_connect);
        v("resolver", c.resolver);
    }
};

namespace system {
namespace {

REGISTER_CONNECTOR(system, [](Proxy &proxy, const auto &ptree) {
    auto config = parse_connector_config<SystemConnectorConfig>(ptree);
    Connector::Options options;
    options.timeout = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::duration<double>(config.timeout));
    options.tcp_no_delay = config.tcp_no_delay;
    options.tcp_fast_open_connect = config.tcp_fast_open_connect;
    for (const std::string &server : config.resolver.server) {
        auto server_addr_port = AddrPort::from_string(server);
        if (!server_addr_port) {
            LOG(error) << "invalid server: " << server;
            continue;
        }
        options.resolver_options.servers.push_back(*server_addr_port);
    }
    const std::string &address_family = config.resolver.address_family;
    if (address_family == "prefer-v4") {
        options.resolver_options.address_family =
            ares::Resolver::AddressFamily::prefer_v4;
    } else if (address_family == "prefer-v6") {
        options.resolver_options.address_family =
            ares::Resolver::AddressFamily::prefer_v6;
    } else if (address_family == "v4-only") {
        options.resolver_options.address_family =
            ares::Resolver::AddressFamily::v4_only;
    } else if (address_family == "v6-only") {
        options.resolver_options.address_family =
            ares::Resolver::AddressFamily::v6_only;
    } else {
        LOG(error) << "invalid address-family: " << address_family;
    }
    return std::make_unique<Connector>(proxy.executor(), options);
});

}  // namespace
}  // namespace system
}  // namespace proxy
}  // namespace net
