#ifndef _NET_PROXY_SHADOWSOCKS_HANDLER_H
#define _NET_PROXY_SHADOWSOCKS_HANDLER_H

#include "net/asio.h"
#include "net/proxy/connector.h"
#include "net/proxy/handler.h"
#include "net/proxy/shadowsocks/pre-shared-key.h"

namespace net {
namespace proxy {
namespace shadowsocks {

class Handler : public proxy::Handler {
public:
    Handler(
        const any_io_executor &executor,
        proxy::Connector &connector);

    struct Config {
        const Method *method = &Method::aes_128_gcm();
        std::string password;
    };

    bool init(const Config &config);

    void handle_stream(
        Stream &stream,
        absl::AnyInvocable<void(std::error_code) &&> callback) override;

private:
    class TcpConnection;

    proxy::Connector &connector_;
    PreSharedKey pre_shared_key_;
};

}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_SHADOWSOCKS_Handler_H
