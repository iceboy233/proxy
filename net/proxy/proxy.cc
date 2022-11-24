#include "net/proxy/proxy.h"

#include "base/logging.h"
#include "net/endpoint.h"
#include "net/proxy/registry.h"

namespace net {
namespace proxy {

Proxy::Proxy(const any_io_executor &executor)
    : executor_(executor) {}

void Proxy::load_config(const boost::property_tree::ptree &config) {
    auto listeners_config = config.get_child("listeners", {});
    auto handlers_config = config.get_child("handlers", {});
    auto connectors_config = config.get_child("connectors", {});
    for (const auto &pair : listeners_config) {
        const auto &listener_config = pair.second;
        std::string endpoint_str = listener_config.get<std::string>(
            "endpoint", "");
        auto endpoint = Endpoint::from_string(endpoint_str);
        if (!endpoint) {
            LOG(error) << "invalid endpoint: " << endpoint_str;
            continue;
        }
        std::string handler_str = listener_config.get<std::string>(
            "handler", "");
        Handler *handler = get_handler(
            handlers_config, connectors_config, handler_str);
        if (!handler) {
            LOG(error) << "invalid handler: " << handler_str;
            continue;
        }
        listeners_.push_back(std::make_unique<system::Listener>(
            executor_, *endpoint, *handler));
    }
}

Handler *Proxy::get_handler(
    const boost::property_tree::ptree &handlers_config,
    const boost::property_tree::ptree &connectors_config,
    std::string_view name) {
    auto iter = handlers_.find(name);
    if (iter != handlers_.end()) {
        return &*iter->second;
    }
    auto handler_config = handlers_config.get_child(std::string(name), {});
    auto handler = Registry::instance().create_handler(
        handler_config.get<std::string>("type", ""),
        executor_,
        [this, &connectors_config](std::string_view connector_name) {
            return get_connector(connectors_config, connector_name);
        },
        handler_config.get_child("settings", {}));
    Handler *handler_ptr = handler.get();
    handlers_[name] = std::move(handler);
    return handler_ptr;
}

Connector *Proxy::get_connector(
    const boost::property_tree::ptree &connectors_config,
    std::string_view name) {
    auto iter = connectors_.find(name);
    if (iter != connectors_.end()) {
        return &*iter->second;
    }
    auto connector_config = connectors_config.get_child(std::string(name), {});
    auto connector = Registry::instance().create_connector(
        connector_config.get<std::string>("type", ""),
        executor_,
        connector_config.get_child("settings", {}));
    Connector *connector_ptr = connector.get();
    connectors_[name] = std::move(connector);
    return connector_ptr;
}

}  // namespace proxy
}  // namespace net
