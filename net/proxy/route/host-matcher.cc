#include "net/proxy/route/host-matcher.h"

#include <cstdlib>
#include <vector>

namespace net {
namespace proxy {
namespace route {

HostMatcher::HostMatcher()
    : set_({}, re2::RE2::ANCHOR_BOTH) {}

void HostMatcher::add(std::string_view host, int value) {
    if (set_.Add(RE2::QuoteMeta(host), nullptr) !=
        static_cast<int>(values_.size())) {
        abort();
    }
    values_.push_back(value);
}

void HostMatcher::add_suffix(std::string_view suffix, int value) {
    if (set_.Add("(.*\\.)?" + RE2::QuoteMeta(suffix), nullptr) !=
        static_cast<int>(values_.size())) {
        abort();
    }
    values_.push_back(value);
}

void HostMatcher::build() {
    if (!set_.Compile()) {
        abort();
    }
}

std::optional<int> HostMatcher::match(std::string_view host) {
    std::vector<int> v;
    if (!set_.Match(host, &v)) {
        return std::nullopt;
    }
    return values_[v.front()];
}

}  // namespace route
}  // namespace proxy
}  // namespace net
