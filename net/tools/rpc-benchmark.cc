#include <chrono>
#include <cstdint>
#include <vector>

#include "base/flags.h"
#include "base/logging.h"
#include "net/asio.h"
#include "net/endpoint.h"
#include "net/rpc/client.h"

DEFINE_FLAG(net::Endpoint, server_endpoint,
            net::Endpoint(net::address_v4::loopback(), 1024), "");
DEFINE_FLAG(size_t, payload_size, 0, "");
DEFINE_FLAG(int, depth, 1, "");

namespace net {
namespace {

std::chrono::high_resolution_clock::time_point start_time;
int64_t total_count = 0;
int64_t error_count = 0;

class BenchmarkClient {
public:
    explicit BenchmarkClient(rpc::Client &rpc_client);

    void start() { request(); }

private:
    void request();

    rpc::Client &rpc_client_;
    udp::endpoint server_endpoint_;
};

class StatsLogger {
public:
    explicit StatsLogger(const net::any_io_executor &executor);

    void start() { wait(); }

private:
    void wait();
    void log();

    net::steady_timer timer_;
};

BenchmarkClient::BenchmarkClient(rpc::Client &rpc_client)
    : rpc_client_(rpc_client),
      server_endpoint_(flags::server_endpoint) {}

void BenchmarkClient::request() {
    std::vector<uint8_t> payload(flags::payload_size);
    rpc_client_.request(
        server_endpoint_, "ping", std::move(payload), {},
        [this](std::error_code ec, const std::vector<uint8_t> &) {
            ++total_count;
            if (ec) {
                ++error_count;
            }
            request();
        });
}

StatsLogger::StatsLogger(const net::any_io_executor &executor)
    : timer_(executor) {}

void StatsLogger::wait() {
    timer_.expires_after(std::chrono::seconds(1));
    timer_.async_wait([this](std::error_code ec) {
        if (ec) {
            LOG(error) << "async_wait failed";
            return;
        }
        log();
    });
}

void StatsLogger::log() {
    std::chrono::nanoseconds time_elapsed =
        std::chrono::high_resolution_clock::now() - start_time;
    LOG(info) << total_count * 1000000000 / time_elapsed.count() << " "
              << error_count * 1000000000 / time_elapsed.count();
    wait();
}

}  // namespace
}  // namespace net

int main(int argc, char *argv[]) {
    using namespace net;

    base::init_logging();
    base::parse_flags(argc, argv);

    io_context io_context;
    auto executor = io_context.get_executor();
    rpc::Client rpc_client(executor, {});
    std::vector<BenchmarkClient> clients;
    clients.reserve(flags::depth);
    start_time = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < flags::depth; ++i) {
        auto &client = clients.emplace_back(rpc_client);
        client.start();
    }
    StatsLogger logger(executor);
    logger.start();
    io_context.run();
}
