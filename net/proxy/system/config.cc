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
    const boost::property_tree::ptree &settings) {
    return std::make_unique<Connector>(executor);
}

REGISTER_CONNECTOR_TYPE("system", create_connector);

}  // namespace
}  // namespace system
}  // namespace proxy
}  // namespace net
