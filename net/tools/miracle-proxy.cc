#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <boost/property_tree/info_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include "base/flags.h"
#include "base/logging.h"
#include "net/asio.h"
#include "net/proxy/proxy.h"
#include "net/proxy/system/stdio-stream.h"
#include "net/proxy/util/copy.h"
#include "util/strings.h"

DEFINE_FLAG(std::string, config, "", "Config file path.");
DEFINE_FLAG(std::string, tcp_connect_target, "",
            "If specified, connects to the specified target instead of "
            "creating the handlers.");
DEFINE_FLAG(std::string, tcp_connect_with, "",
            "Connector used for TCP connect.");

namespace net {
namespace proxy {
namespace {

bool tcp_connect(Proxy &proxy) {
    // TODO(iceboy): Create a class for host:port targets.
    std::string_view target = flags::tcp_connect_target;
    size_t pos = target.rfind(':');
    if (pos == target.npos) {
        LOG(fatal) << "invalid target";
        return false;
    }
    auto host = target.substr(0, pos);
    auto port_str = target.substr(pos + 1);
    uint16_t port = util::consume_uint16(port_str);
    if (!port_str.empty()) {
        LOG(fatal) << "invalid port";
        return false;
    }

    auto *connector = proxy.get_connector(flags::tcp_connect_with);
    if (!connector) {
        LOG(fatal) << "invalid connector";
        return false;
    }
    connector->connect(
        host, port, {},
        [&proxy](std::error_code ec, std::unique_ptr<Stream> remote_stream) {
            if (ec) {
                LOG(error) << "connect failed: " << ec;
                return;
            }
            auto stdio_stream = std::make_unique<system::StdioStream>(
                proxy.executor());
            copy_bidir(
                std::move(remote_stream),
                std::move(stdio_stream),
                [](std::error_code) {
                    // TODO(iceboy): Shutdown instead of exit.
                    exit(0);
                });
        });
    return true;
}

}  // namespace
}  // namespace proxy
}  // namespace net

int main(int argc, char *argv[]) {
    base::init_logging();
    base::parse_flags(argc, argv);

    net::io_context io_context;
    auto executor = io_context.get_executor();
    boost::property_tree::ptree config;
    boost::property_tree::read_info(flags::config, config);
    net::proxy::Proxy proxy(executor);
    net::proxy::Proxy::LoadConfigOptions options;
    if (!flags::tcp_connect_target.empty()) {
        options.create_handlers = false;
    }
    proxy.load_config(config, options);
    if (!flags::tcp_connect_target.empty()) {
        if (!net::proxy::tcp_connect(proxy)) {
            return 1;
        }
    }
    io_context.run();
}
