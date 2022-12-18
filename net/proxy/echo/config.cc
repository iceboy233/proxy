#include "net/proxy/echo/handler.h"
#include "net/proxy/registry.h"

namespace net {
namespace proxy {
namespace echo {
namespace {

std::unique_ptr<Handler> create_handler(
    const any_io_executor &,
    absl::AnyInvocable<Connector *(std::string_view)>,
    const boost::property_tree::ptree &) {
    return std::make_unique<Handler>();
}

REGISTER_HANDLER_TYPE(echo, create_handler);

}  // namespace
}  // namespace echo
}  // namespace proxy
}  // namespace net
