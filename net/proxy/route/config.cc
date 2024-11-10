#include <memory>
#include <string>
#include <utility>
#include <vector>

#include "base/logging.h"
#include "net/proxy/proxy.h"
#include "net/proxy/registry.h"
#include "net/proxy/route/connector.h"
#include "net/proxy/util/config.h"

namespace net {
namespace proxy {

struct RouteConnectorRuleConfig {
    std::vector<std::string> host;
    std::vector<std::string> host_suffix;
    bool default_ = false;
    bool drop = false;
    std::string connector;
};

template <>
struct ConfigVisitor<RouteConnectorRuleConfig> {
    template <typename V>
    void operator()(V &&v, RouteConnectorRuleConfig &c) const {
        v("host", c.host);
        v("host-suffix", c.host_suffix);
        v("default", c.default_);
        v("drop", c.drop);
        v("connector", c.connector);
    }
};

struct RouteConnectorConfig {
    std::vector<RouteConnectorRuleConfig> rule;
};

template <>
struct ConfigVisitor<RouteConnectorConfig> {
    template <typename V>
    void operator()(V &&v, RouteConnectorConfig &c) const {
        v("rule", c.rule);
    }
};

namespace route {
namespace {

REGISTER_CONNECTOR(route, [](Proxy &proxy, const auto &ptree) {
    auto config = parse_connector_config<RouteConnectorConfig>(ptree);
    std::vector<Connector::Rule> rules;
    for (const RouteConnectorRuleConfig &rule_config : config.rule) {
        Connector::Rule rule;
        rule.hosts = rule_config.host;
        rule.host_suffixes = rule_config.host_suffix;
        rule.is_default = rule_config.default_;
        if (!rule_config.drop) {
            rule.connector = proxy.get_connector(rule_config.connector);
            if (!rule.connector) {
                LOG(error) << "invalid connector: " << rule_config.connector;
            }
        }
        rules.push_back(std::move(rule));
    }
    return std::make_unique<Connector>(rules);
});

}  // namespace
}  // namespace route
}  // namespace proxy
}  // namespace net
