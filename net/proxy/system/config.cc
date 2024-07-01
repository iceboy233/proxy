#include <chrono>
#include <memory>
#include <boost/property_tree/ptree.hpp>

#include "base/logging.h"
#include "net/proxy/ares/resolver.h"
#include "net/proxy/proxy.h"
#include "net/proxy/registry.h"
#include "net/proxy/system/connector.h"

namespace net {
namespace proxy {
namespace system {
namespace {

REGISTER_CONNECTOR(system, [](
    Proxy &proxy, const boost::property_tree::ptree &config) {
    Connector::Options options;
    options.timeout = std::chrono::duration_cast<std::chrono::nanoseconds>(
        std::chrono::duration<double>(config.get<double>("timeout", 300)));
    options.tcp_no_delay = config.get<bool>("tcp_no_delay", true);
    const boost::property_tree::ptree empty_ptree;
    const auto &resolver_config = config.get_child("resolver", empty_ptree);
    for (auto iters = resolver_config.equal_range("server");
         iters.first != iters.second;
         ++iters.first) {
        std::string server_str = iters.first->second.get_value<std::string>();
        auto server_endpoint = Endpoint::from_string(server_str);
        if (!server_endpoint) {
            LOG(error) << "invalid server: " << server_str;
            continue;
        }
        options.resolver_options.servers.push_back(*server_endpoint);
    }
    auto address_family = resolver_config.get<std::string>(
        "address-family", "prefer-v4");
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
