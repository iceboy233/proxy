#include "net/proxy/registry.h"

#include <cstdlib>
#include <utility>

#include "base/logging.h"

namespace net {
namespace proxy {

Registry &Registry::instance() {
    // TODO: prevent destruction?
    static Registry registry;
    return registry;
}

void Registry::register_handler(std::string_view type, CreateHandlerFunc func) {
    if (handlers_.contains(type)) {
        LOG(fatal) << "duplicate handler type " << type;
        abort();
        return;
    }
    handlers_[type] = std::move(func);
}

std::unique_ptr<Handler> Registry::create_handler(
    Proxy &proxy, const boost::property_tree::ptree &config) {
    auto type = config.get<std::string>("type", "");
    auto iter = handlers_.find(type);
    if (iter == handlers_.end()) {
        return nullptr;
    }
    return iter->second(proxy, config);
}

void Registry::register_connector(
    std::string_view type, CreateConnectorFunc func) {
    if (connectors_.contains(type)) {
        LOG(fatal) << "duplicate connector type " << type;
        abort();
        return;
    }
    connectors_[type] = std::move(func);
}

std::unique_ptr<Connector> Registry::create_connector(
    Proxy &proxy, const boost::property_tree::ptree &config) {
    auto type = config.get<std::string>("type", "");
    auto iter = connectors_.find(type);
    if (iter == connectors_.end()) {
        return nullptr;
    }
    return iter->second(proxy, config);
}

}  // namespace proxy
}  // namespace net
