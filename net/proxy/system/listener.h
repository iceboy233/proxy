#ifndef _NET_PROXY_SYSTEM_LISTENER_H
#define _NET_PROXY_SYSTEM_LISTENER_H

#include "net/asio.h"
#include "net/endpoint.h"
#include "net/proxy/handler.h"

namespace net {
namespace proxy {
namespace system {

class Listener {
public:
    Listener(
        const any_io_executor &executor,
        const Endpoint &endpoint,
        Handler &handler);

private:
    void accept();

    any_io_executor executor_;
    tcp::acceptor tcp_acceptor_;
    Handler &handler_;
};

}  // namespace system
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_SYSTEM_LISTENER_H
