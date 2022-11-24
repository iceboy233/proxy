#include <memory>
#include <boost/property_tree/ptree.hpp>

#include "base/logging.h"
#include "net/asio.h"
#include "net/proxy/registry.h"
#include "net/proxy/shadowsocks/handler.h"

namespace net {
namespace proxy {
namespace shadowsocks {
namespace {

std::unique_ptr<Handler> create_handler(
    const any_io_executor &executor,
    absl::AnyInvocable<Connector *(std::string_view)> get_connector_func,
    const boost::property_tree::ptree &settings) {
    Handler::Config config;
    std::string method = settings.get<std::string>("method", "");
    config.method = Method::find(method);
    if (!config.method) {
        LOG(error) << "invalid method: " << method;
        return nullptr;
    }
    config.password = settings.get<std::string>("password", "");
    std::string connector_str = settings.get<std::string>("connector", "");
    Connector *connector = get_connector_func(connector_str);
    if (!connector) {
        LOG(error) << "invalid connector: " << connector_str;
        return nullptr;
    }
    auto handler = std::make_unique<Handler>(executor, *connector);
    if (!handler->init(config)) {
        LOG(error) << "init failed";
        return nullptr;
    }
    return handler;
}

REGISTER_HANDLER_TYPE("shadowsocks", create_handler);

}  // namespace
}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net
