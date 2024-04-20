#include <boost/property_tree/info_parser.hpp>
#include <boost/property_tree/ptree.hpp>

#include "base/flags.h"
#include "base/logging.h"
#include "net/asio.h"
#include "net/proxy/proxy.h"

DEFINE_FLAG(std::string, config, "", "Config file path.");

int main(int argc, char *argv[]) {
    base::init_logging();
    base::parse_flags(argc, argv);

    net::io_context io_context;
    auto executor = io_context.get_executor();
    boost::property_tree::ptree config;
    boost::property_tree::read_info(flags::config, config);
    net::proxy::Proxy proxy(executor);
    net::proxy::Proxy::LoadConfigOptions options;
    proxy.load_config(config, options);
    io_context.run();
}
