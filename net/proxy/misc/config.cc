#include <memory>

#include "net/proxy/misc/echo-handler.h"
#include "net/proxy/misc/null-handler.h"
#include "net/proxy/misc/random-handler.h"
#include "net/proxy/misc/zero-handler.h"
#include "net/proxy/registry.h"

namespace net {
namespace proxy {
namespace misc {
namespace {

REGISTER_HANDLER(echo, [](Proxy &, const auto &) {
    return std::make_unique<EchoHandler>();
});

REGISTER_HANDLER(null, [](Proxy &, const auto &) {
    return std::make_unique<NullHandler>();
});

REGISTER_HANDLER(random, [](Proxy &, const auto &) {
    return std::make_unique<RandomHandler>();
});

REGISTER_HANDLER(zero, [](Proxy &, const auto &) {
    return std::make_unique<ZeroHandler>();
});

}  // namespace
}  // namespace misc
}  // namespace proxy
}  // namespace net
