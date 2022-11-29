#include <chrono>
#include <memory>
#include <boost/property_tree/ptree.hpp>

#include "net/asio.h"
#include "net/proxy/registry.h"
#include "net/proxy/system/connector.h"

namespace net {
namespace proxy {
namespace system {
namespace {

std::unique_ptr<Connector> create_connector(
    const any_io_executor &executor,
    absl::AnyInvocable<proxy::Connector *(std::string_view)> get_connector_func,
    const boost::property_tree::ptree &settings) {
    Connector::Options options;
    options.timeout = std::chrono::nanoseconds(static_cast<int64_t>(
        settings.get<double>("timeout", 300) * 1000000000));
    options.tcp_no_delay = settings.get<bool>("tcp_no_delay", true);
    return std::make_unique<Connector>(executor, options);
}

REGISTER_CONNECTOR_TYPE(system, create_connector);

}  // namespace
}  // namespace system
}  // namespace proxy
}  // namespace net
