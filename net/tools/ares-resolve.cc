#include <ostream>
#include <string_view>
#include <system_error>

#include "base/logging.h"
#include "io/posix/file.h"
#include "io/stream.h"
#include "net/asio.h"
#include "net/blocking-result.h"
#include "net/proxy/ares/resolver.h"
#include "net/proxy/system/connector.h"

int main(int argc, char *argv[]) {
    using namespace net;

    base::init_logging();

    io_context io_context;
    auto executor = io_context.get_executor();
    proxy::system::Connector connector(executor, {});
    BlockingResult<std::error_code, std::vector<address>> results[argc - 1];
    for (int i = 1; i < argc; ++i) {
        connector.resolver().resolve(argv[i], results[i - 1].callback());
    }

    io::OStream os(io::posix::stdout);
    for (int i = 1; i < argc; ++i) {
        auto &result = results[i - 1];
        result.run(io_context);
        if (std::get<0>(result.args())) {
            LOG(error) << "resolve failed: " << std::get<0>(result.args());
            continue;
        }
        os << argv[i];
        for (const address &address : std::get<1>(result.args())) {
            os << ' ' << address;
        }
        os << std::endl;
    }
}
