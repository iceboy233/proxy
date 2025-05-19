#ifndef _NET_PROXY_SOCKS_CONNECTOR_H
#define _NET_PROXY_SOCKS_CONNECTOR_H

#include "net/interface/connector.h"
#include "net/types/addr-port.h"

namespace net {
namespace proxy {
namespace socks {

class Connector : public net::Connector {
public:
    Connector(net::Connector &connector, const AddrPort &server)
        : connector_(connector),
          server_(server) {}

    void connect(
        const HostPort &target,
        const_buffer initial_data,
        absl::AnyInvocable<void(
            std::error_code, std::unique_ptr<Stream>) &&> callback) override;

    std::error_code bind(
        const udp::endpoint &endpoint,
        std::unique_ptr<Datagram> &datagram) override;

private:
    class TcpStream;

    net::Connector &connector_;
    AddrPort server_;
};

}  // namespace socks
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_SOCKS_CONNECTOR_H
