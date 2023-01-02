#include "net/proxy/proxy.h"

#include <chrono>
#include <functional>

#include "absl/functional/bind_front.h"
#include "base/logging.h"
#include "net/endpoint.h"
#include "net/proxy/registry.h"

namespace net {
namespace proxy {

Proxy::Proxy(const any_io_executor &executor)
    : executor_(executor) {}

void Proxy::load_config(const boost::property_tree::ptree &config) {
    auto listeners_config = config.get_child("listeners", {});
    auto connectors_config = config.get_child("connectors", {});
    if (connectors_config.find("") == connectors_config.not_found()) {
        boost::property_tree::ptree default_connector;
        default_connector.put("type", "system");
        connectors_config.push_back({"", default_connector});
    }
    for (const auto &pair : listeners_config) {
        const auto &listener_config = pair.second;
        std::string listen_str = listener_config.get<std::string>("listen", "");
        auto listen_endpoint = Endpoint::from_string(listen_str);
        if (!listen_endpoint) {
            LOG(error) << "invalid listen endpoint: " << listen_str;
            continue;
        }
        auto handler = Registry::instance().create_handler(
            listener_config.get<std::string>("type", ""),
            executor_,
            absl::bind_front(
                &Proxy::get_connector, this, std::ref(connectors_config)),
            listener_config);
        if (!handler) {
            LOG(error) << "failed to create handler";
            continue;
        }
        auto &handler_ref = *handler;
        handlers_.push_back(std::move(handler));
        system::Listener::Options options;
        options.timeout = std::chrono::nanoseconds(static_cast<int64_t>(
            listener_config.get<double>("timeout", 300) * 1000000000));
        options.tcp_no_delay = listener_config.get<bool>("tcp_no_delay", true);
        listeners_.push_back(std::make_unique<system::Listener>(
            executor_, *listen_endpoint, handler_ref, options));
    }
}

Connector *Proxy::get_connector(
    const boost::property_tree::ptree &connectors_config,
    std::string_view name) {
    auto iter = connectors_.find(name);
    if (iter != connectors_.end()) {
        return &*iter->second;
    }
    auto config_iter = connectors_config.find(std::string(name));
    if (config_iter == connectors_config.not_found()) {
        return nullptr;
    }
    const auto &connector_config = config_iter->second;
    auto connector = Registry::instance().create_connector(
        connector_config.get<std::string>("type", ""),
        executor_,
        absl::bind_front(
            &Proxy::get_connector, this, std::ref(connectors_config)),
        connector_config);
    Connector *connector_ptr = connector.get();
    connectors_[name] = std::move(connector);
    return connector_ptr;
}

}  // namespace proxy
}  // namespace net
