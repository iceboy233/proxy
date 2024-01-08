#ifndef _NET_PROXY_MISC_RANDOM_HANDLER_H
#define _NET_PROXY_MISC_RANDOM_HANDLER_H

#include "net/proxy/handler.h"

namespace net {
namespace proxy {
namespace misc {

class RandomHandler : public Handler {
public:
    void handle_stream(std::unique_ptr<Stream> stream) override;
    void handle_datagram(std::unique_ptr<Datagram> datagram) override;
};

}  // namespace misc
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_MISC_RANDOM_HANDLER_H
