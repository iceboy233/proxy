#include <chrono>
#include <cstdint>
#include <optional>

#include "base/flags.h"
#include "base/logging.h"
#include "net/asio.h"
#include "net/endpoint.h"
#include "net/shadowsocks/encryption.h"
#include "net/shadowsocks/tcp-server.h"
#include "net/shadowsocks/udp-server.h"

DEFINE_FLAG(net::Endpoint, endpoint,
            net::Endpoint(net::address_v4::loopback(), 8388), "");
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
DEFINE_FLAG(uint64_t, tcp_forward_bytes_rate_limit, 0, "");
DEFINE_FLAG(uint64_t, tcp_backward_bytes_rate_limit, 0, "");
DEFINE_FLAG(uint64_t, udp_forward_packets_rate_limit, 0, "");
DEFINE_FLAG(uint64_t, udp_backward_packets_rate_limit, 0, "");

namespace net {
namespace shadowsocks {
namespace {

void create_tcp_server(
    const any_io_executor &executor,
    const MasterKey &master_key,
    std::optional<SaltFilter> &salt_filter,
    std::optional<TcpServer> &tcp_server) {
    TcpServer::Options options;
    if (salt_filter) {
        options.salt_filter = &*salt_filter;
    }
    options.connection_timeout = std::chrono::seconds(
        flags::tcp_connection_timeout_secs);
    options.forward_bytes_rate_limit = flags::tcp_forward_bytes_rate_limit;
    options.backward_bytes_rate_limit = flags::tcp_backward_bytes_rate_limit;
    tcp_server.emplace(executor, flags::endpoint, master_key, options);
}

void create_udp_server(
    const any_io_executor &executor,
    const MasterKey &master_key,
    std::optional<SaltFilter> &salt_filter,
    std::optional<UdpServer> &udp_server) {
    UdpServer::Options options;
    if (salt_filter) {
        options.salt_filter = &*salt_filter;
    }
    options.connection_timeout = std::chrono::seconds(
        flags::udp_connection_timeout_secs);
    options.forward_packets_rate_limit = flags::udp_forward_packets_rate_limit;
    options.backward_packets_rate_limit =
        flags::udp_backward_packets_rate_limit;
    udp_server.emplace(executor, flags::endpoint, master_key, options);
}

}  // namespace
}  // namespace shadowsocks
}  // namespace net

int main(int argc, char *argv[]) {
    using namespace net::shadowsocks;

    base::init_logging();
    base::parse_flags(argc, argv);

    net::io_context io_context;
    auto executor = io_context.get_executor();
    MasterKey master_key;
    master_key.init(flags::method, flags::password);
    std::optional<SaltFilter> salt_filter;
    if (flags::detect_salt_reuse) {
        salt_filter.emplace();
    }
    std::optional<TcpServer> tcp_server;
    if (flags::enable_tcp) {
        create_tcp_server(executor, master_key, salt_filter, tcp_server);
    }
    std::optional<UdpServer> udp_server;
    if (flags::enable_udp) {
        create_udp_server(executor, master_key, salt_filter, udp_server);
    }
    io_context.run();
}
