#ifndef _NET_PROXY_REGISTRY_H
#define _NET_PROXY_REGISTRY_H

#include <string>
#include <string_view>
#include <boost/property_tree/ptree.hpp>

#include "absl/container/flat_hash_map.h"
#include "absl/functional/any_invocable.h"
#include "net/asio.h"
#include "net/proxy/connector.h"
#include "net/proxy/handler.h"

namespace net {
namespace proxy {

class Proxy;

class Registry {
public:
    static Registry &instance();

    using HandlerCreateFunc = absl::AnyInvocable<std::unique_ptr<Handler>(
        const any_io_executor &executor,
        absl::AnyInvocable<Connector *(std::string_view)> get_connector_func,
        const boost::property_tree::ptree &settings)>;

    void register_handler_type(
        std::string_view type,
        HandlerCreateFunc create_func);

    std::unique_ptr<Handler> create_handler(
        std::string_view type,
        const any_io_executor &executor,
        absl::AnyInvocable<Connector *(std::string_view)> get_connector_func,
        const boost::property_tree::ptree &settings);

    using ConnectorCreateFunc = absl::AnyInvocable<std::unique_ptr<Connector>(
        const any_io_executor &executor,
        absl::AnyInvocable<Connector *(std::string_view)> get_connector_func,
        const boost::property_tree::ptree &settings)>;

    void register_connector_type(
        std::string_view type,
        ConnectorCreateFunc create_func);

    std::unique_ptr<Connector> create_connector(
        std::string_view type,
        const any_io_executor &executor,
        absl::AnyInvocable<Connector *(std::string_view)> get_connector_func,
        const boost::property_tree::ptree &settings);

private:
    Registry() = default;

    absl::flat_hash_map<std::string, HandlerCreateFunc> handler_types_;
    absl::flat_hash_map<std::string, ConnectorCreateFunc> connector_types_;
};

}  // namespace proxy
}  // namespace net

#define REGISTER_HANDLER_TYPE(_type, _create_func) \
    namespace { \
    auto register_handler_type##_create_func = []() { \
        net::proxy::Registry::instance().register_handler_type( \
            #_type, _create_func); \
        return 0; \
    }(); \
    } \

#define REGISTER_CONNECTOR_TYPE(_type, _create_func) \
    namespace { \
    auto register_connector_type##_create_func = []() { \
        net::proxy::Registry::instance().register_connector_type( \
            #_type, _create_func); \
        return 0; \
    }(); \
    } \

#endif  // _NET_PROXY_REGISTRY_H
