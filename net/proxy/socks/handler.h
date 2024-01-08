#ifndef _NET_PROXY_SOCKS_HANDLER_H
#define _NET_PROXY_SOCKS_HANDLER_H

#include "net/asio.h"
#include "net/proxy/connector.h"
#include "net/proxy/handler.h"

namespace net {
namespace proxy {
namespace socks {

class Handler : public proxy::Handler {
public:
    Handler(const any_io_executor &executor, proxy::Connector &connector);

    void handle_stream(std::unique_ptr<Stream> stream) override;
    void handle_datagram(std::unique_ptr<Datagram> datagram) override;

private:
    class TcpConnection;

    proxy::Connector &connector_;
};

}  // namespace socks
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_SOCKS_HANDLER_H
