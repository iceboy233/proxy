#include <chrono>
#include <memory>
#include <boost/property_tree/ptree.hpp>

#include "net/proxy/proxy.h"
#include "net/proxy/registry.h"
#include "net/proxy/system/connector.h"

namespace net {
namespace proxy {
namespace system {
namespace {

REGISTER_CONNECTOR(system, [](
    Proxy &proxy, const boost::property_tree::ptree &config) {
    Connector::Options options;
    options.timeout = std::chrono::nanoseconds(static_cast<int64_t>(
        config.get<double>("timeout", 300) * 1000000000));
    options.tcp_no_delay = config.get<bool>("tcp_no_delay", true);
    return std::make_unique<Connector>(proxy.executor(), options);
});

}  // namespace
}  // namespace system
}  // namespace proxy
}  // namespace net
