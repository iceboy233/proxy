#ifndef _NET_PROXY_ROUTE_HOST_MATCHER_H
#define _NET_PROXY_ROUTE_HOST_MATCHER_H

#include <optional>
#include <string_view>
#include <vector>

#include "re2/set.h"

namespace net {
namespace proxy {
namespace route {

class HostMatcher {
public:
    HostMatcher();

    void add(std::string_view host, int value);
    void add_suffix(std::string_view host_suffix, int value);
    void build();
    std::optional<int> match(std::string_view host);

private:
    re2::RE2::Set set_;
    std::vector<int> values_;
};

}  // namespace route
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_ROUTE_HOST_MATCHER_H
