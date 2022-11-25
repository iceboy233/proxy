#ifndef _NET_PROXY_HANDLER_H
#define _NET_PROXY_HANDLER_H

#include <memory>

#include "net/proxy/stream.h"

namespace net {
namespace proxy {

class Handler {
public:
    virtual ~Handler() = default;

    virtual void handle_stream(std::unique_ptr<Stream> stream) = 0;
};

}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_HANDLER_H
