#include <memory>
#include <string>

#include "base/logging.h"
#include "net/proxy/proxy.h"
#include "net/proxy/registry.h"
#include "net/proxy/socks/connector.h"
#include "net/proxy/socks/handler.h"
#include "net/proxy/util/config.h"
#include "net/types/addr-port.h"

namespace net {
namespace proxy {

struct SocksHandlerConfig {
    std::string connector;
};

template <>
struct ConfigVisitor<SocksHandlerConfig> {
    template <typename V>
    void operator()(V &&v, SocksHandlerConfig &c) const {
        v("connector", c.connector);
    }
};

struct SocksConnectorConfig {
    std::string server;
    std::string connector;
};

template <>
struct ConfigVisitor<SocksConnectorConfig> {
    template <typename V>
    void operator()(V &&v, SocksConnectorConfig &c) const {
        v("server", c.server);
        v("connector", c.connector);
    }
};

namespace socks {
namespace {

REGISTER_HANDLER(socks, [](
    Proxy &proxy, const auto &ptree) -> std::unique_ptr<Handler> {
    auto config = parse_handler_config<SocksHandlerConfig>(ptree);
    net::Connector *connector = proxy.get_connector(config.connector);
    if (!connector) {
        LOG(error) << "invalid connector: " << config.connector;
        return nullptr;
    }
    return std::make_unique<Handler>(proxy.executor(), *connector);
});

REGISTER_CONNECTOR(socks, [](
    Proxy &proxy, const auto &ptree) -> std::unique_ptr<Connector> {
    auto config = parse_connector_config<SocksConnectorConfig>(ptree);
    auto server_addr_port = AddrPort::from_string(config.server);
    if (!server_addr_port) {
        LOG(error) << "invalid server: " << config.server;
        return nullptr;
    }
    net::Connector *connector = proxy.get_connector(config.connector);
    if (!connector) {
        LOG(error) << "invalid connector: " << config.connector;
        return nullptr;
    }
    return std::make_unique<Connector>(*connector, *server_addr_port);
});

}  // namespace
}  // namespace socks
}  // namespace proxy
}  // namespace net
