#include "net/proxy/route/host-matcher.h"

#include <cstdlib>
#include <vector>

namespace net {
namespace proxy {
namespace route {

HostMatcher::HostMatcher()
    : set_({}, re2::RE2::ANCHOR_BOTH) {}

int HostMatcher::add(std::string_view host) {
    int ret = set_.Add(RE2::QuoteMeta(host), nullptr);
    if (ret < 0) {
        abort();
    }
    return ret;
}

int HostMatcher::add_suffix(std::string_view suffix) {
    int ret = set_.Add("(.*\\.)?" + RE2::QuoteMeta(suffix), nullptr);
    if (ret < 0) {
        abort();
    }
    return ret;
}

void HostMatcher::build() {
    if (!set_.Compile()) {
        abort();
    }
}

int HostMatcher::match(std::string_view host) {
    std::vector<int> v;
    if (!set_.Match(host, &v)) {
        return -1;
    }
    return v.front();
}

}  // namespace route
}  // namespace proxy
}  // namespace net
