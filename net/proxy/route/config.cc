#include <memory>
#include <utility>
#include <boost/property_tree/ptree.hpp>

#include "base/logging.h"
#include "net/proxy/proxy.h"
#include "net/proxy/registry.h"
#include "net/proxy/route/connector.h"

namespace net {
namespace proxy {
namespace route {
namespace {

Connector::Rule parse_rule(
    Proxy &proxy,
    const boost::property_tree::ptree &rule_config) {
    Connector::Rule rule;
    for (auto iters = rule_config.equal_range("host");
         iters.first != iters.second;
         ++iters.first) {
        std::string host = iters.first->second.get_value<std::string>();
        rule.hosts.push_back(std::move(host));
    }
    for (auto iters = rule_config.equal_range("host-suffix");
         iters.first != iters.second;
         ++iters.first) {
        std::string host_suffix = iters.first->second.get_value<std::string>();
        rule.host_suffixes.push_back(std::move(host_suffix));
    }
    if (rule_config.get<bool>("default", false)) {
        rule.is_default = true;
    }
    if (!rule_config.get<bool>("drop", false)) {
        std::string connector = rule_config.get<std::string>("connector", "");
        rule.connector = proxy.get_connector(connector);
        if (!rule.connector) {
            LOG(error) << "invalid connector: " << connector;
        }
    }
    return rule;
}

REGISTER_CONNECTOR(route, [](
    Proxy &proxy,
    const boost::property_tree::ptree &config) -> std::unique_ptr<Connector> {
    std::vector<Connector::Rule> rules;
    for (auto iters = config.equal_range("rule");
         iters.first != iters.second;
         ++iters.first) {
        rules.push_back(parse_rule(proxy, iters.first->second));
    }
    return std::make_unique<Connector>(rules);
});

}  // namespace
}  // namespace route
}  // namespace proxy
}  // namespace net
