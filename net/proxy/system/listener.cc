#include "net/proxy/system/listener.h"

#include <chrono>

#include "base/logging.h"
#include "net/proxy/system/tcp-socket-stream.h"

namespace net {
namespace proxy {
namespace system {

Listener::Listener(
    const any_io_executor &executor,
    const Endpoint &endpoint,
    Handler &handler,
    const Options &options)
    : executor_(executor),
      tcp_acceptor_(executor, endpoint),
      handler_(handler),
      timer_list_(executor_, options.timeout),
      tcp_no_delay_(options.tcp_no_delay),
      accept_error_delay_(options.accept_error_delay),
      accept_error_timer_(executor_) { accept(); }

void Listener::accept() {
    tcp_acceptor_.async_accept(
        [this](std::error_code ec, tcp::socket socket) mutable {
            if (ec) {
                LOG(error) << "accept failed: " << ec;
                accept_error_wait();
                return;
            }
            auto stream = std::make_unique<TcpSocketStream>(
                std::move(socket), timer_list_);
            if (tcp_no_delay_) {
                stream->socket().set_option(tcp::no_delay(true));
            }
            handler_.handle_stream(std::move(stream));
            accept();
        });
}

void Listener::accept_error_wait() {
    accept_error_timer_.expires_after(accept_error_delay_);
    accept_error_timer_.async_wait([this](std::error_code ec) {
        if (ec) {
            LOG(error) << "async_wait failed: " << ec;
            return;
        }
        accept();
    });
}

}  // namespace system
}  // namespace proxy
}  // namespace net
