#include <memory>
#include <boost/property_tree/ptree.hpp>

#include "absl/functional/any_invocable.h"
#include "base/logging.h"
#include "net/asio.h"
#include "net/proxy/registry.h"
#include "net/proxy/shadowsocks/connector.h"
#include "net/proxy/shadowsocks/handler.h"

namespace net {
namespace proxy {
namespace shadowsocks {
namespace {

std::unique_ptr<Handler> create_handler(
    const any_io_executor &executor,
    absl::AnyInvocable<proxy::Connector *(std::string_view)> get_connector_func,
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
    proxy::Connector *connector = get_connector_func(connector_str);
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

std::unique_ptr<Connector> create_connector(
    const any_io_executor &executor,
    absl::AnyInvocable<proxy::Connector *(std::string_view)> get_connector_func,
    const boost::property_tree::ptree &settings) {
    Connector::Config config;
    for (auto iters = settings.equal_range("server");
         iters.first != iters.second;
         ++iters.first) {
        std::string server_str = iters.first->second.get_value<std::string>();
        auto server_endpoint = Endpoint::from_string(server_str);
        if (!server_endpoint) {
            LOG(error) << "invalid server endpoint: " << server_str;
            continue;
        }
        config.endpoints.push_back(*server_endpoint);
    }
    std::string method = settings.get<std::string>("method", "");
    config.method = Method::find(method);
    if (!config.method) {
        LOG(error) << "invalid method: " << method;
        return nullptr;
    }
    config.password = settings.get<std::string>("password", "");
    config.min_padding_length = settings.get<size_t>("min-padding-length", 1);
    config.max_padding_length = settings.get<size_t>("max-padding-length", 900);
    std::string connector_str = settings.get<std::string>("connector", "");
    proxy::Connector *base_connector = get_connector_func(connector_str);
    if (!base_connector) {
        LOG(error) << "invalid connector: " << connector_str;
        return nullptr;
    }
    auto connector = std::make_unique<Connector>(executor, *base_connector);
    if (!connector->init(config)) {
        LOG(error) << "init failed";
        return nullptr;
    }
    return connector;
}

REGISTER_HANDLER_TYPE(shadowsocks, create_handler);
REGISTER_CONNECTOR_TYPE(shadowsocks, create_connector);

}  // namespace
}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net
