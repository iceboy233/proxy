#ifndef _NET_PROXY_SYSTEM_LISTENER_H
#define _NET_PROXY_SYSTEM_LISTENER_H

#include <chrono>

#include "net/asio.h"
#include "net/timer-list.h"
#include "net/interface/handler.h"
#include "net/types/addr-port.h"

namespace net {
namespace proxy {
namespace system {

class Listener {
public:
    struct Options {
        std::chrono::nanoseconds timeout = std::chrono::minutes(5);
        bool tcp_no_delay = true;
        int tcp_fast_open = 5;
        std::chrono::nanoseconds accept_error_delay =
            std::chrono::milliseconds(500);
    };

    Listener(
        const any_io_executor &executor,
        const AddrPort &listen,
        Handler &handler,
        const Options &options);

private:
    void accept();
    void accept_error_wait();
    void bind();

    any_io_executor executor_;
    AddrPort listen_;
    Handler &handler_;
    tcp::acceptor tcp_acceptor_;
    TimerList timer_list_;
    bool tcp_no_delay_;
    std::chrono::nanoseconds accept_error_delay_;
    steady_timer accept_error_timer_;
};

}  // namespace system
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_SYSTEM_LISTENER_H
