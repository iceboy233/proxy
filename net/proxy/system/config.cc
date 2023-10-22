#include <chrono>
#include <memory>
#include <boost/property_tree/ptree.hpp>

#include "base/logging.h"
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
    const auto &resolver_config = config.get_child("resolver", {});
    for (auto iters = resolver_config.equal_range("server");
         iters.first != iters.second;
         ++iters.first) {
        std::string server_str = iters.first->second.get_value<std::string>();
        auto server_endpoint = Endpoint::from_string(server_str);
        if (!server_endpoint) {
            LOG(error) << "invalid server endpoint: " << server_str;
            continue;
        }
        options.resolver_options.servers.push_back(*server_endpoint);
    }
    return std::make_unique<Connector>(proxy.executor(), options);
});

}  // namespace
}  // namespace system
}  // namespace proxy
}  // namespace net
