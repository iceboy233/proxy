#ifndef _NET_PROXY_SYSTEM_LISTENER_H
#define _NET_PROXY_SYSTEM_LISTENER_H

#include <chrono>

#include "net/asio.h"
#include "net/endpoint.h"
#include "net/proxy/handler.h"
#include "net/timer-list.h"

namespace net {
namespace proxy {
namespace system {

class Listener {
public:
    struct Options {
        std::chrono::nanoseconds timeout = std::chrono::minutes(5);
        bool tcp_no_delay = true;
    };

    Listener(
        const any_io_executor &executor,
        const Endpoint &endpoint,
        Handler &handler,
        const Options &options);

private:
    void accept();

    any_io_executor executor_;
    tcp::acceptor tcp_acceptor_;
    Handler &handler_;
    TimerList timer_list_;
    bool tcp_no_delay_;
};

}  // namespace system
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_SYSTEM_LISTENER_H
