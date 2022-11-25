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

void Registry::register_handler_type(
    std::string_view type, HandlerCreateFunc create_func) {
    if (handler_types_.contains(type)) {
        LOG(fatal) << "multiple handler type " << type;
        abort();
        return;
    }
    handler_types_[type] = std::move(create_func);
}

std::unique_ptr<Handler> Registry::create_handler(
    std::string_view type,
    const any_io_executor &executor,
    absl::AnyInvocable<Connector *(std::string_view)> get_connector_func,
    const boost::property_tree::ptree &settings) {
    auto iter = handler_types_.find(type);
    if (iter == handler_types_.end()) {
        return nullptr;
    }
    return iter->second(executor, std::move(get_connector_func), settings);
}

void Registry::register_connector_type(
    std::string_view type, ConnectorCreateFunc create_func) {
    if (connector_types_.contains(type)) {
        LOG(fatal) << "multiple connector type " << type;
        abort();
        return;
    }
    connector_types_[type] = std::move(create_func);
}

std::unique_ptr<Connector> Registry::create_connector(
    std::string_view type,
    const any_io_executor &executor,
    absl::AnyInvocable<Connector *(std::string_view)> get_connector_func,
    const boost::property_tree::ptree &settings) {
    auto iter = connector_types_.find(type);
    if (iter == connector_types_.end()) {
        return nullptr;
    }
    return iter->second(executor, std::move(get_connector_func), settings);
}

}  // namespace proxy
}  // namespace net
