#include "base/flags.h"
#include "base/logging.h"
#include "io/posix/file.h"
#include "io/stream.h"
#include "net/asio.h"
#include "net/asio-flags.h"
#include "net/blocking-result.h"
#include "net/icmp-client.h"

DEFINE_FLAG(net::address, ip_from, {}, "");
DEFINE_FLAG(net::address, ip_to, {}, "");
DEFINE_FLAG(int32_t, rps, 1000, "");
DEFINE_FLAG(size_t, request_size, 0, "");

namespace net {
namespace {

void request(
    io_context &io_context,
    IcmpClient &icmp_client,
    steady_timer &timer,
    const icmp::endpoint &endpoint,
    std::ostream &os,
    int64_t &pending_requests) {
    auto start_time = std::chrono::steady_clock::now();
    timer.expires_at(
        start_time +
            std::chrono::nanoseconds(std::chrono::seconds(1)) / flags::rps);
    ++pending_requests;
    icmp_client.request(
        endpoint,
        std::vector<uint8_t>(flags::request_size),
        [address = endpoint.address(), start_time, &os, &pending_requests](
            std::error_code ec, ConstBufferSpan) {
            if (ec) {
                if (ec != make_error_code(std::errc::timed_out)) {
                    LOG(error) << "request failed: " << ec;
                }
                --pending_requests;
                return;
            }
            auto end_time = std::chrono::steady_clock::now();
            os << address << " "
               << std::chrono::duration_cast<std::chrono::microseconds>(
                      end_time - start_time).count()
               << std::endl;
            --pending_requests;
        });
    BlockingResult<std::error_code> wait_result;
    timer.async_wait(wait_result.callback());
    wait_result.run(io_context);
    if (std::get<0>(wait_result.args())) {
        LOG(error) << "wait failed: " << std::get<0>(wait_result.args());
    }
}

}  // namespace
}  // namespace net

int main(int argc, char *argv[]) {
    using namespace net;

    base::init_logging();
    base::parse_flags(argc, argv);

    io_context io_context;
    auto executor = io_context.get_executor();
    IcmpClient icmp_client(executor, {});
    steady_timer timer(executor);
    io::OStream os(io::posix::stdout);
    int64_t pending_requests = 0;
    if (flags::ip_from.is_v4()) {
        address_v4_iterator first(flags::ip_from.to_v4());
        address_v4_iterator last(flags::ip_to.to_v4());
        for (; first != last; ++first) {
            request(
                io_context, icmp_client, timer, {*first, 0}, os,
                pending_requests);
        }
    } else {
        address_v6_iterator first(flags::ip_from.to_v6());
        address_v6_iterator last(flags::ip_to.to_v6());
        for (; first != last; ++first) {
            request(
                io_context, icmp_client, timer, {*first, 0}, os,
                pending_requests);
        }
    }
    while (pending_requests && io_context.run_one()) {}
}
