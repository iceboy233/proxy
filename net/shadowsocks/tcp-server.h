#ifndef _NET_SHADOWSOCKS_TCP_SERVER_H
#define _NET_SHADOWSOCKS_TCP_SERVER_H

#include "net/asio.h"
#include "net/shadowsocks/aes-crypto.h"

namespace net {
namespace shadowsocks {

// The provided executor must be single-threaded, and all functions must be
// called in the executor thread.
class TcpServer {
public:
    TcpServer(
        const any_io_executor &executor,
        const tcp::endpoint &endpoint,
        const AesMasterKey &master_key);

private:
    class Connection;

    void accept();

    any_io_executor executor_;
    AesMasterKey master_key_;
    tcp::acceptor acceptor_;
    tcp::resolver resolver_;
};

}  // namespace shadowsocks
}  // namespace net

#endif  // _NET_SHADOWSOCKS_TCP_SERVER_H
