#ifndef _NET_PROXY_PROXY_H
#define _NET_PROXY_PROXY_H

#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <boost/property_tree/ptree.hpp>

#include "absl/container/flat_hash_map.h"
#include "net/asio.h"
#include "net/proxy/connector.h"
#include "net/proxy/handler.h"
#include "net/proxy/system/listener.h"

namespace net {
namespace proxy {

class Proxy {
public:
    Proxy(const any_io_executor &executor);

    void load_config(const boost::property_tree::ptree &config);
    Connector *get_connector(std::string_view name);

    const any_io_executor &executor() const { return executor_; }

private:
    void create_handlers();

    any_io_executor executor_;
    boost::property_tree::ptree handlers_config_;
    boost::property_tree::ptree connectors_config_;
    std::vector<std::unique_ptr<system::Listener>> listeners_;
    std::vector<std::unique_ptr<Handler>> handlers_;
    absl::flat_hash_map<std::string, std::unique_ptr<Connector>> connectors_;
};

}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_PROXY_H
