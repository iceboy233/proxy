#ifndef _NET_PROXY_ECHO_HANDLER_H
#define _NET_PROXY_ECHO_HANDLER_H

#include "net/proxy/handler.h"

namespace net {
namespace proxy {
namespace echo {

class Handler : public proxy::Handler {
public:
    void handle_stream(std::unique_ptr<Stream> stream) override;
};

}  // namespace echo
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_ECHO_HANDLER_H
