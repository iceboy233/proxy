#include "net/proxy/system/listener.h"

#include <chrono>

#include "base/logging.h"
#include "net/proxy/system/tcp-socket-stream.h"
#include "net/proxy/system/udp-socket-datagram.h"

namespace net {
namespace proxy {
namespace system {

Listener::Listener(
    const any_io_executor &executor,
    const AddrPort &listen,
    Handler &handler,
    const Options &options)
    : executor_(executor),
      listen_(listen),
      handler_(handler),
      tcp_acceptor_(executor_, listen_),
      timer_list_(executor_, options.timeout),
      tcp_no_delay_(options.tcp_no_delay),
      accept_error_delay_(options.accept_error_delay),
      accept_error_timer_(executor_) {
    // TODO: Support more flexible config, such as enabling TCP or UDP
    // individually, using different handlers, and live config reloading.
#ifdef TCP_FASTOPEN
    if (options.tcp_fast_open > 0) {
        boost::system::error_code ec;
        tcp_acceptor_.set_option(
            boost::asio::detail::socket_option::integer<
                IPPROTO_TCP, TCP_FASTOPEN>(options.tcp_fast_open), ec);
        if (ec) {
            LOG(error) << "set_option failed for fast_open: " << ec;
        }
    }
#endif
    accept();
    bind();
}

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

void Listener::bind() {
    udp::socket socket(executor_, listen_);
    handler_.handle_datagram(
        std::make_unique<UdpSocketDatagram>(std::move(socket)));
}

}  // namespace system
}  // namespace proxy
}  // namespace net
