#include <chrono>
#include <cstdint>
#include <optional>

#include "base/flags.h"
#include "base/logging.h"
#include "net/asio.h"
#include "net/asio-flags.h"
#include "net/shadowsocks/encryption.h"
#include "net/shadowsocks/tcp-server.h"
#include "net/shadowsocks/udp-server.h"

DEFINE_FLAG(net::address, ip, net::address_v4::loopback(), "");
DEFINE_FLAG(uint16_t, port, 8388, "");
DEFINE_FLAG(bool, enable_tcp, true, "");
DEFINE_FLAG(bool, enable_udp, true, "");
DEFINE_FLAG(std::string, password, "", "");
DEFINE_FLAG(std::string, method, "aes-128-gcm",
            "Supported encryption methods: aes-128-gcm, aes-192-gcm, "
            "aes-256-gcm, chacha20-ietf-poly1305, xchacha20-ietf-poly1305");
DEFINE_FLAG(bool, detect_salt_reuse, true,
            "Detect salt reuse to prevent replay attacks.");
DEFINE_FLAG(int, tcp_connection_timeout_secs, 300, "");
DEFINE_FLAG(int, udp_connection_timeout_secs, 300, "");

int main(int argc, char *argv[]) {
    using namespace net::shadowsocks;

    base::init_logging();
    base::parse_flags(argc, argv);

    net::io_context io_context;
    auto executor = io_context.get_executor();
    MasterKey master_key(EncryptionMethod::from_name(flags::method));
    master_key.init_with_password(flags::password);
    std::optional<SaltFilter> salt_filter;
    if (flags::detect_salt_reuse) {
        salt_filter.emplace();
    }
    std::optional<TcpServer> tcp_server;
    if (flags::enable_tcp) {
        TcpServer::Options options;
        if (salt_filter) {
            options.salt_filter = &*salt_filter;
        }
        options.connection_timeout = std::chrono::seconds(
            flags::tcp_connection_timeout_secs);
        tcp_server.emplace(
            executor,
            net::tcp::endpoint(flags::ip, flags::port),
            master_key,
            options);
    }
    std::optional<UdpServer> udp_server;
    if (flags::enable_udp) {
        UdpServer::Options options;
        if (salt_filter) {
            options.salt_filter = &*salt_filter;
        }
        options.connection_timeout = std::chrono::seconds(
            flags::udp_connection_timeout_secs);
        udp_server.emplace(
            executor,
            net::udp::endpoint(flags::ip, flags::port),
            master_key,
            options);
    }
    io_context.run();
}
