#include <memory>
#include <boost/property_tree/ptree.hpp>

#include "base/logging.h"
#include "net/proxy/proxy.h"
#include "net/proxy/registry.h"
#include "net/proxy/socks/handler.h"

namespace net {
namespace proxy {
namespace socks {
namespace {

REGISTER_HANDLER(socks, [](
    Proxy &proxy,
    const boost::property_tree::ptree &config) -> std::unique_ptr<Handler> {
    std::string connector_str = config.get<std::string>("connector", "");
    Connector *connector = proxy.get_connector(connector_str);
    if (!connector) {
        LOG(error) << "invalid connector: " << connector_str;
        return nullptr;
    }
    return std::make_unique<Handler>(proxy.executor(), *connector);
});

}  // namespace
}  // namespace socks
}  // namespace proxy
}  // namespace net
