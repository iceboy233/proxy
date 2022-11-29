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
      tcp_no_delay_(options.tcp_no_delay) { accept(); }

void Listener::accept() {
    tcp_acceptor_.async_accept(
        [this](std::error_code ec, tcp::socket socket) mutable {
            if (ec) {
                LOG(fatal) << "accept failed: " << ec;
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

}  // namespace system
}  // namespace proxy
}  // namespace net
