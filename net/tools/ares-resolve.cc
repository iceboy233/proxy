#include <ostream>
#include <string_view>
#include <system_error>

#include "absl/types/span.h"
#include "base/logging.h"
#include "io/posix/file.h"
#include "io/stream.h"
#include "net/asio.h"
#include "net/proxy/ares/resolver.h"
#include "net/proxy/system/connector.h"

int main(int argc, char *argv[]) {
    using namespace net;

    base::init_logging();

    io_context io_context;
    auto executor = io_context.get_executor();
    proxy::system::Connector connector(executor, {});
    proxy::ares::Resolver resolver(executor, connector, {});
    io::OStream os(io::posix::stdout);
    for (int i = 1; i < argc; ++i) {
        std::string_view host = argv[i];
        resolver.resolve(
            host,
            [&os, host](
                std::error_code ec, absl::Span<address const> addresses) {
                if (ec) {
                    LOG(error) << "resolve failed: " << ec;
                    return;
                }
                os << host;
                for (const address &address : addresses) {
                    os << ' ' << address;
                }
                os << std::endl;
            });
    }
    io_context.run();
}
