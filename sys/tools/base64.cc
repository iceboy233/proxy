#include <array>
#include <string>
#include <system_error>

#include "absl/strings/escaping.h"
#include "base/flags.h"
#include "io/file-utils.h"
#include "io/posix/file.h"

DEFINE_FLAG(bool, d, false, "Decode.");
DEFINE_FLAG(bool, url, false, "Use URL encoding.");

namespace sys {
namespace {

std::error_code encode() {
    std::array<char, 6144> src;
    std::string dest;
    dest.reserve(8192);

    size_t size;
    do {
        std::error_code ec = read(io::posix::stdin, src, size);
        if (ec) {
            return ec;
        }
        if (!flags::url) {
            absl::Base64Escape({src.data(), size}, &dest);
        } else {
            absl::WebSafeBase64Escape({src.data(), size}, &dest);
        }
        ec = write(io::posix::stdout, dest);
        if (ec) {
            return ec;
        }
    } while (size == src.size());
    return {};
}

std::error_code decode() {
    std::array<char, 8192> src;
    std::string dest;
    dest.reserve(6144);

    size_t size;
    do {
        std::error_code ec = read(io::posix::stdin, src, size);
        if (ec) {
            return ec;
        }
        bool success;
        if (!flags::url) {
            success = absl::Base64Unescape({src.data(), size}, &dest);
        } else {
            success = absl::WebSafeBase64Unescape({src.data(), size}, &dest);
        }
        if (!success) {
            return make_error_code(std::errc::bad_message);
        }
        ec = write(io::posix::stdout, dest);
        if (ec) {
            return ec;
        }
    } while (size == src.size());
    return {};
}

}  // namespace
}  // namespace sys

int main(int argc, char *argv[]) {
    using namespace sys;

    base::parse_flags(argc, argv);

    if (!flags::d) {
        return encode().value();
    } else {
        return decode().value();
    }
}
