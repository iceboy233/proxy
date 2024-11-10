#include <memory>
#include <string>

#include "base/logging.h"
#include "net/proxy/proxy.h"
#include "net/proxy/registry.h"
#include "net/proxy/socks/handler.h"
#include "net/proxy/util/config.h"

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

namespace socks {
namespace {

REGISTER_HANDLER(socks, [](
    Proxy &proxy, const auto &ptree) -> std::unique_ptr<Handler> {
    auto config = parse_handler_config<SocksHandlerConfig>(ptree);
    Connector *connector = proxy.get_connector(config.connector);
    if (!connector) {
        LOG(error) << "invalid connector: " << config.connector;
        return nullptr;
    }
    return std::make_unique<Handler>(proxy.executor(), *connector);
});

}  // namespace
}  // namespace socks
}  // namespace proxy
}  // namespace net
