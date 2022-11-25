#include <memory>
#include <boost/property_tree/ptree.hpp>

#include "absl/functional/any_invocable.h"
#include "base/logging.h"
#include "net/asio.h"
#include "net/proxy/registry.h"
#include "net/proxy/socks/handler.h"

namespace net {
namespace proxy {
namespace socks {
namespace {

std::unique_ptr<Handler> create_handler(
    const any_io_executor &executor,
    absl::AnyInvocable<Connector *(std::string_view)> get_connector_func,
    const boost::property_tree::ptree &settings) {
    std::string connector_str = settings.get<std::string>("connector", "");
    Connector *connector = get_connector_func(connector_str);
    if (!connector) {
        LOG(error) << "invalid connector: " << connector_str;
        return nullptr;
    }
    return std::make_unique<Handler>(executor, *connector);
}

REGISTER_HANDLER_TYPE(socks, create_handler);

}  // namespace
}  // namespace socks
}  // namespace proxy
}  // namespace net
