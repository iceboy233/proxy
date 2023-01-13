#ifndef _NET_PROXY_ROUTE_HOST_MATCHER_H
#define _NET_PROXY_ROUTE_HOST_MATCHER_H

#include <string_view>

#include "re2/set.h"

namespace net {
namespace proxy {
namespace route {

class HostMatcher {
public:
    HostMatcher();

    int add(std::string_view host);
    int add_suffix(std::string_view host_suffix);
    void build();
    int match(std::string_view host);

private:
    re2::RE2::Set set_;
};

}  // namespace route
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_ROUTE_HOST_MATCHER_H
