#include "net/proxy/util/config.h"

#include "base/logging.h"

namespace net {
namespace proxy {

PropertyTreeVisitor::PropertyTreeVisitor(
    const boost::property_tree::ptree &ptree,
    absl::flat_hash_set<std::string> known_fields)
    : ptree_(ptree),
      known_fields_(std::move(known_fields)) {}

void PropertyTreeVisitor::operator()(const char *name, std::string &value) {
    if (auto optional = ptree_.get_optional<std::string>(name); optional) {
        value = optional.value();
    }
    known_fields_.insert(name);
}

void PropertyTreeVisitor::operator()(
    const char *name, std::vector<std::string> &values) {
    values.clear();
    for (auto iters = ptree_.equal_range(name);
         iters.first != iters.second; ++iters.first) {
        values.push_back(iters.first->second.get_value<std::string>());
    }
    known_fields_.insert(name);
}

void PropertyTreeVisitor::log_unknown_fields() const {
    for (const auto &pair : ptree_) {
        if (!known_fields_.contains(pair.first)) {
            LOG(warning) << "unknown field: " << pair.first;
        }
    }
}

}  // namespace proxy
}  // namespace net
