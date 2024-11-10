#ifndef _NET_PROXY_UTIL_CONFIG_H
#define _NET_PROXY_UTIL_CONFIG_H

#include <cstdint>
#include <string>
#include <type_traits>
#include <utility>
#include <vector>
#include <boost/property_tree/ptree.hpp>

#include "absl/container/flat_hash_set.h"

namespace net {
namespace proxy {

template <typename ConfigT>
struct ConfigVisitor {};

class PropertyTreeVisitor {
public:
    PropertyTreeVisitor(
        const boost::property_tree::ptree &ptree,
        absl::flat_hash_set<std::string> known_fields);

    void operator()(const char *name, std::string &value);
    void operator()(const char *name, std::vector<std::string> &values);

    template <
        typename T,
        std::enable_if_t<std::is_arithmetic_v<T>, bool> = true>
    void operator()(const char *name, T &value) {
        if (auto optional = ptree_.get_optional<T>(name); optional) {
            value = optional.value();
        }
        known_fields_.insert(name);
    }

    template <
        typename ConfigT,
        std::enable_if_t<std::is_void_v<
            decltype(ConfigVisitor<ConfigT>()(
                std::declval<PropertyTreeVisitor>(),
                std::declval<ConfigT &>()))>, bool> = true>
    void operator()(const char *name, ConfigT &config) {
        if (auto optional = ptree_.get_child_optional(name); optional) {
            parse_config(*optional, config);
        }
        known_fields_.insert(name);
    }

    template <
        typename ConfigT,
        std::enable_if_t<std::is_void_v<
            decltype(ConfigVisitor<ConfigT>()(
                std::declval<PropertyTreeVisitor>(),
                std::declval<ConfigT &>()))>, bool> = true>
    void operator()(const char *name, std::vector<ConfigT> &configs) {
        configs.clear();
        for (auto iters = ptree_.equal_range(name);
             iters.first != iters.second; ++iters.first) {
            parse_config(iters.first->second, configs.emplace_back());
        }
        known_fields_.insert(name);
    }

    void log_unknown_fields() const;

private:
    const boost::property_tree::ptree &ptree_;
    absl::flat_hash_set<std::string> known_fields_;
};

template <typename ConfigT>
void parse_config(
    const boost::property_tree::ptree &ptree,
    ConfigT &config,
    absl::flat_hash_set<std::string> known_fields = {}) {
    PropertyTreeVisitor ptree_visitor(ptree, std::move(known_fields));
    ConfigVisitor<ConfigT>()(ptree_visitor, config);
    ptree_visitor.log_unknown_fields();
}

template <typename ConfigT>
ConfigT parse_connector_config(const boost::property_tree::ptree &ptree) {
    ConfigT config;
    parse_config(ptree, config, {"type"});
    return config;
}

template <typename ConfigT>
ConfigT parse_handler_config(const boost::property_tree::ptree &ptree) {
    ConfigT config;
    parse_config(ptree, config, {"listen", "type", "timeout", "tcp_no_delay"});
    return config;
}

}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_UTIL_CONFIG_H
