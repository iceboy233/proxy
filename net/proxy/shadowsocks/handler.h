#ifndef _NET_PROXY_SHADOWSOCKS_HANDLER_H
#define _NET_PROXY_SHADOWSOCKS_HANDLER_H

#include "net/asio.h"
#include "net/interface/connector.h"
#include "net/interface/handler.h"
#include "net/proxy/shadowsocks/pre-shared-key.h"
#include "net/proxy/shadowsocks/salt-filter.h"

namespace net {
namespace proxy {
namespace shadowsocks {

class Handler : public net::Handler {
public:
    explicit Handler(net::Connector &connector)
        : connector_(connector) {}

    struct InitOptions {
        const Method *method = &Method::aes_128_gcm();
        std::string password;
    };

    bool init(const InitOptions &config);

    void handle_stream(std::unique_ptr<Stream> stream) override;
    void handle_datagram(std::unique_ptr<Datagram> datagram) override;

private:
    class TcpConnection;

    net::Connector &connector_;
    PreSharedKey pre_shared_key_;
    SaltFilter salt_filter_;
};

}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_SHADOWSOCKS_HANDLER_H
