#ifndef _NET_SOCKS_TCP_SERVER_H
#define _NET_SOCKS_TCP_SERVER_H

#include "net/asio.h"

namespace net {
namespace socks {

class TcpServer {
public:
    struct Options {};

    TcpServer(
        const any_io_executor &executor,
        const tcp::endpoint &endpoint,
        const Options &options);

    void accept();

private:
    class Connection;

    any_io_executor executor_;
    tcp::acceptor acceptor_;
    tcp::resolver resolver_;
};

}  // namespace socks
}  // namespace net

#endif  // _NET_SOCKS_TCP_SERVER_H
