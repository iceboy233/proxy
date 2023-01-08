#include <memory>
#include <boost/property_tree/ptree.hpp>

#include "base/logging.h"
#include "net/proxy/proxy.h"
#include "net/proxy/registry.h"
#include "net/proxy/shadowsocks/connector.h"
#include "net/proxy/shadowsocks/handler.h"

namespace net {
namespace proxy {
namespace shadowsocks {
namespace {

REGISTER_HANDLER(shadowsocks, [](
    Proxy &proxy,
    const boost::property_tree::ptree &config) -> std::unique_ptr<Handler> {
    Handler::InitOptions options;
    std::string method = config.get<std::string>("method", "");
    options.method = Method::find(method);
    if (!options.method) {
        LOG(error) << "invalid method: " << method;
        return nullptr;
    }
    options.password = config.get<std::string>("password", "");
    std::string connector_str = config.get<std::string>("connector", "");
    proxy::Connector *connector = proxy.get_connector(connector_str);
    if (!connector) {
        LOG(error) << "invalid connector: " << connector_str;
        return nullptr;
    }
    auto handler = std::make_unique<Handler>(proxy.executor(), *connector);
    if (!handler->init(options)) {
        LOG(error) << "init failed";
        return nullptr;
    }
    return handler;
});

REGISTER_CONNECTOR(shadowsocks, [](
    Proxy &proxy,
    const boost::property_tree::ptree &config) -> std::unique_ptr<Connector> {
    Connector::InitOptions options;
    for (auto iters = config.equal_range("server");
         iters.first != iters.second;
         ++iters.first) {
        std::string server_str = iters.first->second.get_value<std::string>();
        auto server_endpoint = Endpoint::from_string(server_str);
        if (!server_endpoint) {
            LOG(error) << "invalid server endpoint: " << server_str;
            continue;
        }
        options.endpoints.push_back(*server_endpoint);
    }
    std::string method = config.get<std::string>("method", "");
    options.method = Method::find(method);
    if (!options.method) {
        LOG(error) << "invalid method: " << method;
        return nullptr;
    }
    options.password = config.get<std::string>("password", "");
    options.min_padding_length = config.get<size_t>("min-padding-length", 1);
    options.max_padding_length = config.get<size_t>("max-padding-length", 900);
    std::string connector_str = config.get<std::string>("connector", "");
    proxy::Connector *base_connector = proxy.get_connector(connector_str);
    if (!base_connector) {
        LOG(error) << "invalid connector: " << connector_str;
        return nullptr;
    }
    auto connector = std::make_unique<Connector>(
        proxy.executor(), *base_connector);
    if (!connector->init(options)) {
        LOG(error) << "init failed";
        return nullptr;
    }
    return connector;
});

}  // namespace
}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net
