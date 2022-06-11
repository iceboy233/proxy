#include <functional>
#include <memory>
#include <string_view>
#include <tuple>
#include <utility>
#include <vector>

#include "absl/strings/escaping.h"
#include "absl/strings/numbers.h"
#include "base/flags.h"
#include "base/logging.h"
#include "net/asio.h"
#include "net/endpoint.h"
#include "net/rpc/client.h"
#include "net/rpc/server.h"
#include "security/key.h"

DEFINE_FLAG(net::Endpoint, endpoint,
            net::Endpoint(net::address_v4::loopback(), 1024), "");
DEFINE_FLAG(std::vector<std::string>, methods, {},
            "Comma-separated list of method:ip:port.");
DEFINE_FLAG(std::vector<std::string>, keys, {}, "");

namespace net {
namespace {

class RpcRelayHandler : public rpc::Handler {
public:
    RpcRelayHandler(
        rpc::Client &client,
        std::string_view method,
        const udp::endpoint &endpoint);

    void handle(
        std::vector<uint8_t> request,
        const security::Key &key,
        std::function<void(std::vector<uint8_t>)> callback) override;

private:
    rpc::Client &client_;
    std::string method_;
    udp::endpoint endpoint_;
};

RpcRelayHandler::RpcRelayHandler(
    rpc::Client &client,
    std::string_view method,
    const udp::endpoint &endpoint)
    : client_(client),
      method_(method),
      endpoint_(endpoint) {}

void RpcRelayHandler::handle(
    std::vector<uint8_t> request,
    const security::Key &key,
    std::function<void(std::vector<uint8_t>)> callback) {
    rpc::Client::RequestOptions options;
    options.key = key;
    // TODO(iceboy): Timeout.
    client_.request(
        endpoint_, method_, std::move(request), options,
        [callback = std::move(callback)](
            std::error_code ec, std::vector<uint8_t> response) {
            if (ec) {
                LOG(error) << "request failed: " << ec;
                return;
            }
            callback(std::move(response));
        });
}

}  // namespace
}  // namespace net

int main(int argc, char *argv[]) {
    using namespace net;

    base::init_logging();
    base::parse_flags(argc, argv);

    io_context io_context;
    auto executor = io_context.get_executor();
    rpc::Server server(executor, flags::endpoint, {});
    rpc::Client client(executor, {});

    for (const std::string &key_string : flags::keys) {
        // TODO(iceboy): Use a better implementation.
        std::string key_bytes = absl::HexStringToBytes(key_string);
        security::KeyArray key_array;
        if (key_bytes.size() != key_array.size()) {
            LOG(fatal) << "invalid key size";
            return 1;
        }
        std::copy_n(key_bytes.begin(), key_bytes.size(), key_array.begin());
        server.add_key(security::Key(key_array));
    }

    for (const std::string &method_string : flags::methods) {
        std::vector<std::string_view> split = absl::StrSplit(
            method_string, absl::MaxSplits(':', 3));
        if (split.size() != 3) {
            LOG(fatal) << "invalid method specification";
            return 1;
        }
        auto address = make_address(split[1]);
        // TODO(iceboy): Parse uint16_t natively.
        uint32_t port32;
        if (!absl::SimpleAtoi(split[2], &port32) ||
            port32 > std::numeric_limits<uint16_t>::max()) {
            LOG(fatal) << "invalid port";
            return 1;
        }
        server.handle(
            split[0],
            std::make_unique<RpcRelayHandler>(
                client,
                split[0],
                udp::endpoint(address, static_cast<uint16_t>(port32))));
    }

    server.start();
    io_context.run();
}
