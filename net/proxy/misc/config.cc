#include "net/proxy/misc/echo-handler.h"
#include "net/proxy/misc/null-handler.h"
#include "net/proxy/misc/random-handler.h"
#include "net/proxy/misc/zero-handler.h"
#include "net/proxy/registry.h"

namespace net {
namespace proxy {
namespace misc {
namespace {

std::unique_ptr<Handler> create_echo_handler(
    const any_io_executor &,
    absl::AnyInvocable<Connector *(std::string_view)>,
    const boost::property_tree::ptree &) {
    return std::make_unique<EchoHandler>();
}

std::unique_ptr<Handler> create_null_handler(
    const any_io_executor &,
    absl::AnyInvocable<Connector *(std::string_view)>,
    const boost::property_tree::ptree &) {
    return std::make_unique<NullHandler>();
}

std::unique_ptr<Handler> create_random_handler(
    const any_io_executor &,
    absl::AnyInvocable<Connector *(std::string_view)>,
    const boost::property_tree::ptree &) {
    return std::make_unique<RandomHandler>();
}

std::unique_ptr<Handler> create_zero_handler(
    const any_io_executor &,
    absl::AnyInvocable<Connector *(std::string_view)>,
    const boost::property_tree::ptree &) {
    return std::make_unique<ZeroHandler>();
}

REGISTER_HANDLER_TYPE(echo, create_echo_handler);
REGISTER_HANDLER_TYPE(null, create_null_handler);
REGISTER_HANDLER_TYPE(random, create_random_handler);
REGISTER_HANDLER_TYPE(zero, create_zero_handler);

}  // namespace
}  // namespace misc
}  // namespace proxy
}  // namespace net
