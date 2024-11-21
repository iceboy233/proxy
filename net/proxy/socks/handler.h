#ifndef _NET_PROXY_SOCKS_HANDLER_H
#define _NET_PROXY_SOCKS_HANDLER_H

#include "net/asio.h"
#include "net/interface/connector.h"
#include "net/interface/handler.h"

namespace net {
namespace proxy {
namespace socks {

class Handler : public net::Handler {
public:
    Handler(const any_io_executor &executor, net::Connector &connector);

    void handle_stream(std::unique_ptr<Stream> stream) override;
    void handle_datagram(std::unique_ptr<Datagram> datagram) override;

private:
    class TcpConnection;

    net::Connector &connector_;
};

}  // namespace socks
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_SOCKS_HANDLER_H
