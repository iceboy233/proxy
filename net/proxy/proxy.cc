#include "net/proxy/proxy.h"

#include <chrono>
#include <functional>

#include "base/logging.h"
#include "net/endpoint.h"
#include "net/proxy/registry.h"

namespace net {
namespace proxy {

Proxy::Proxy(const any_io_executor &executor)
    : executor_(executor) {}

void Proxy::load_config(const boost::property_tree::ptree &config) {
    handlers_config_ = config.get_child("handlers", {});
    auto listeners_config = config.get_child("listeners", {});
    if (!listeners_config.empty()) {
        LOG(warning) << "listeners is deprecated, rename to handlers instead";
        handlers_config_.insert(
            handlers_config_.end(),
            listeners_config.begin(),
            listeners_config.end());
    }
    connectors_config_ = config.get_child("connectors", {});
    if (connectors_config_.find("") == connectors_config_.not_found()) {
        boost::property_tree::ptree default_connector;
        default_connector.put("type", "system");
        connectors_config_.push_back({"", default_connector});
    }
    create_handlers();
}

void Proxy::create_handlers() {
    for (const auto &pair : handlers_config_) {
        const auto &config = pair.second;
        std::string listen_str = config.get<std::string>("listen", "");
        auto listen_endpoint = Endpoint::from_string(listen_str);
        if (!listen_endpoint) {
            LOG(error) << "invalid listen endpoint: " << listen_str;
            continue;
        }
        auto handler = Registry::instance().create_handler(*this, config);
        if (!handler) {
            LOG(error) << "failed to create handler";
            continue;
        }
        auto &handler_ref = *handler;
        handlers_.push_back(std::move(handler));
        system::Listener::Options options;
        options.timeout = std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::duration<double>(config.get<double>("timeout", 300)));
        options.tcp_no_delay = config.get<bool>("tcp_no_delay", true);
        listeners_.push_back(std::make_unique<system::Listener>(
            executor_, *listen_endpoint, handler_ref, options));
    }
}

Connector *Proxy::get_connector(std::string_view name) {
    auto iter = connectors_.find(name);
    if (iter != connectors_.end()) {
        return &*iter->second;
    }
    auto config_iter = connectors_config_.find(std::string(name));
    if (config_iter == connectors_config_.not_found()) {
        return nullptr;
    }
    const auto &config = config_iter->second;
    auto connector = Registry::instance().create_connector(*this, config);
    Connector *connector_ptr = connector.get();
    connectors_[name] = std::move(connector);
    return connector_ptr;
}

}  // namespace proxy
}  // namespace net
