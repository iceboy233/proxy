#include <cstdint>

#include "base/flags.h"
#include "base/logging.h"
#include "net/asio.h"
#include "net/asio-flags.h"
#include "net/shadowsocks/encryption.h"
#include "net/shadowsocks/tcp-server.h"
#include "net/shadowsocks/udp-server.h"

DEFINE_FLAG(net::address, ip, net::address_v4::loopback(), "");
DEFINE_FLAG(uint16_t, port, 8388, "");
DEFINE_FLAG(std::string, password, "", "");
DEFINE_FLAG(std::string, method, "aes-128-gcm",
            "Supported encryption methods: aes-128-gcm, aes-192-gcm, "
            "aes-256-gcm, chacha20-ietf-poly1305");
DEFINE_FLAG(int, tcp_connection_timeout_secs, 300, "");
DEFINE_FLAG(int, udp_connection_timeout_secs, 300, "");

int main(int argc, char *argv[]) {
    using namespace net::shadowsocks;

    base::init_logging();
    base::parse_flags(argc, argv);

    net::io_context io_context;
    MasterKey master_key(EncryptionMethod::from_name(flags::method));
    master_key.init_with_password(flags::password);
    SaltFilter salt_filter;
    TcpServer::Options tcp_options;
    tcp_options.connection_timeout = std::chrono::seconds(
        flags::tcp_connection_timeout_secs);
    TcpServer tcp_server(
        io_context.get_executor(),
        net::tcp::endpoint(flags::ip, flags::port),
        master_key,
        salt_filter,
        tcp_options);
    UdpServer::Options udp_options;
    udp_options.connection_timeout = std::chrono::seconds(
        flags::udp_connection_timeout_secs);
    UdpServer udp_server(
        io_context.get_executor(),
        net::udp::endpoint(flags::ip, flags::port),
        master_key,
        salt_filter,
        udp_options);
    io_context.run();
}
