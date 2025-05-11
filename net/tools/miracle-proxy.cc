#include <cstdint>
#include <memory>
#include <string>
#include <system_error>
#include <utility>
#include <boost/property_tree/info_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include "base/flags.h"
#include "base/logging.h"
#include "net/asio.h"
#include "net/blocking-result.h"
#include "net/proxy/proxy.h"
#include "net/proxy/system/stdio-stream.h"
#include "net/proxy/util/copy.h"
#include "net/types/host-port.h"

DEFINE_FLAG(std::string, config, "", "Config file path.");
DEFINE_FLAG(net::HostPort, tcp_connect_target, {},
            "If specified, connects to the specified target instead of "
            "creating the handlers.");
DEFINE_FLAG(std::string, tcp_connect_with, "",
            "Connector used for TCP connect.");

namespace net {
namespace proxy {
namespace {

std::error_code tcp_connect(Proxy &proxy, io_context &io_context) {
    auto *connector = proxy.get_connector(flags::tcp_connect_with);
    if (!connector) {
        LOG(fatal) << "invalid connector";
        return make_error_code(std::errc::invalid_argument);
    }
    BlockingResult<std::error_code, std::unique_ptr<Stream>> connect_result;
    connector->connect(
        flags::tcp_connect_target, {}, connect_result.callback());
    connect_result.run(io_context);
    if (std::get<0>(connect_result.args())) {
        LOG(error) << "connect failed: " << std::get<0>(connect_result.args());
        return std::get<0>(connect_result.args());
    }
    BlockingResult<std::error_code> copy_bidir_result;
    copy_bidir(
        std::get<1>(std::move(connect_result.args())),
        std::make_unique<system::StdioStream>(io_context.get_executor()),
        copy_bidir_result.callback());
    copy_bidir_result.run(io_context);
    return {};
}

}  // namespace
}  // namespace proxy
}  // namespace net

int main(int argc, char *argv[]) {
    base::init_logging();
    base::parse_flags(argc, argv);

    net::io_context io_context;
    boost::property_tree::ptree config;
    boost::property_tree::read_info(flags::config, config);
    net::proxy::Proxy proxy(io_context.get_executor());
    net::proxy::Proxy::LoadConfigOptions options;
    if (!flags::tcp_connect_target.empty()) {
        options.create_handlers = false;
    }
    proxy.load_config(config, options);
    if (!flags::tcp_connect_target.empty()) {
        return net::proxy::tcp_connect(proxy, io_context).value();
    }
    io_context.run();
}
