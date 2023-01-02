#include "net/proxy/ares/error-category.h"

#include <ares.h>

namespace net {
namespace proxy {
namespace ares {
namespace {

class ErrorCategory : public std::error_category {
public:
    const char *name() const noexcept override { return "ares"; }
    std::string message(int condition) const override;
};

std::string ErrorCategory::message(int condition) const {
    return ares_strerror(condition);
}

const ErrorCategory category;

}  // namespace

const std::error_category &error_category() {
    return category;
}

}  // namespace ares
}  // namespace proxy
}  // namespace net
