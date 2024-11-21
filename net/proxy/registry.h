#ifndef _NET_PROXY_REGISTRY_H
#define _NET_PROXY_REGISTRY_H

#include <string>
#include <string_view>
#include <boost/property_tree/ptree.hpp>

#include "absl/container/flat_hash_map.h"
#include "absl/functional/any_invocable.h"
#include "net/asio.h"
#include "net/interface/connector.h"
#include "net/interface/handler.h"

namespace net {
namespace proxy {

class Proxy;

class Registry {
public:
    static Registry &instance();

    using CreateHandlerFunc = absl::AnyInvocable<std::unique_ptr<Handler>(
        Proxy &proxy, const boost::property_tree::ptree &config)>;

    void register_handler(std::string_view type, CreateHandlerFunc func);

    std::unique_ptr<Handler> create_handler(
        Proxy &proxy, const boost::property_tree::ptree &config);

    using CreateConnectorFunc = absl::AnyInvocable<std::unique_ptr<Connector>(
        Proxy &proxy, const boost::property_tree::ptree &config)>;

    void register_connector(std::string_view type, CreateConnectorFunc func);

    std::unique_ptr<Connector> create_connector(
        Proxy &proxy, const boost::property_tree::ptree &config);

private:
    Registry() = default;

    absl::flat_hash_map<std::string, CreateHandlerFunc> handlers_;
    absl::flat_hash_map<std::string, CreateConnectorFunc> connectors_;
};

}  // namespace proxy
}  // namespace net

#define REGISTER_HANDLER(_type, _create_func) \
    namespace { \
    auto register_handler_##_type = []() { \
        net::proxy::Registry::instance().register_handler( \
            #_type, _create_func); \
        return 0; \
    }(); \
    } \

#define REGISTER_CONNECTOR(_type, _create_func) \
    namespace { \
    auto register_connector_##_type = []() { \
        net::proxy::Registry::instance().register_connector( \
            #_type, _create_func); \
        return 0; \
    }(); \
    } \

#endif  // _NET_PROXY_REGISTRY_H
