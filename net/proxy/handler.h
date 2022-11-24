#ifndef _NET_PROXY_HANDLER_H
#define _NET_PROXY_HANDLER_H

#include <memory>
#include <system_error>

#include "absl/functional/any_invocable.h"
#include "net/proxy/stream.h"

namespace net {
namespace proxy {

class Handler {
public:
    virtual ~Handler() = default;

    virtual void handle_stream(
        Stream &stream,
        absl::AnyInvocable<void(std::error_code) &&> callback) = 0;
};

}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_HANDLER_H
