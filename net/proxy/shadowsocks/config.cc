#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "base/logging.h"
#include "net/proxy/proxy.h"
#include "net/proxy/registry.h"
#include "net/proxy/shadowsocks/connector.h"
#include "net/proxy/shadowsocks/handler.h"
#include "net/proxy/util/config.h"

namespace net {
namespace proxy {

struct ShadowsocksHandlerConfig {
    std::string method;
    std::string password;
    std::string connector;
};

template <>
struct ConfigVisitor<ShadowsocksHandlerConfig> {
    template <typename V>
    void operator()(V &&v, ShadowsocksHandlerConfig &c) const {
        v("method", c.method);
        v("password", c.password);
        v("connector", c.connector);
    }
};

struct ShadowsocksConnectorConfig {
    std::vector<std::string> server;
    std::string method;
    std::string password;
    uint32_t min_padding_length = 1;
    uint32_t max_padding_length = 900;
    std::string connector;
};

template <>
struct ConfigVisitor<ShadowsocksConnectorConfig> {
    template <typename V>
    void operator()(V &&v, ShadowsocksConnectorConfig &c) const {
        v("server", c.server);
        v("method", c.method);
        v("password", c.password);
        v("min-padding-length", c.min_padding_length);
        v("max-padding-length", c.max_padding_length);
        v("connector", c.connector);
    }
};

namespace shadowsocks {
namespace {

REGISTER_HANDLER(shadowsocks, [](
    Proxy &proxy, const auto &ptree) -> std::unique_ptr<Handler> {
    auto config = parse_handler_config<ShadowsocksHandlerConfig>(ptree);
    Handler::InitOptions options;
    options.method = Method::find(config.method);
    if (!options.method) {
        LOG(error) << "invalid method: " << config.method;
        return nullptr;
    }
    options.password = config.password;
    proxy::Connector *connector = proxy.get_connector(config.connector);
    if (!connector) {
        LOG(error) << "invalid connector: " << config.connector;
        return nullptr;
    }
    auto handler = std::make_unique<Handler>(*connector);
    if (!handler->init(options)) {
        LOG(error) << "init failed";
        return nullptr;
    }
    return handler;
});

REGISTER_CONNECTOR(shadowsocks, [](
    Proxy &proxy, const auto &ptree) -> std::unique_ptr<Connector> {
    auto config = parse_connector_config<ShadowsocksConnectorConfig>(ptree);
    Connector::InitOptions options;
    for (const std::string &server : config.server) {
        auto server_endpoint = Endpoint::from_string(server);
        if (!server_endpoint) {
            LOG(error) << "invalid server: " << server;
            continue;
        }
        options.endpoints.push_back(*server_endpoint);
    }
    options.method = Method::find(config.method);
    if (!options.method) {
        LOG(error) << "invalid method: " << config.method;
        return nullptr;
    }
    options.password = config.password;
    options.min_padding_length = config.min_padding_length;
    options.max_padding_length = config.max_padding_length;
    proxy::Connector *base_connector = proxy.get_connector(config.connector);
    if (!base_connector) {
        LOG(error) << "invalid connector: " << config.connector;
        return nullptr;
    }
    auto connector = std::make_unique<Connector>(*base_connector);
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
