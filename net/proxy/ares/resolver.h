#ifndef _NET_PROXY_ARES_RESOLVER_H
#define _NET_PROXY_ARES_RESOLVER_H

#include <ares.h>
#include <string_view>
#include <system_error>
#include <vector>
#include <boost/smart_ptr/intrusive_ptr.hpp>

#include "absl/container/flat_hash_map.h"
#include "absl/functional/any_invocable.h"
#include "net/asio.h"
#include "net/proxy/ares/socket.h"
#include "net/proxy/connector.h"
#include "net/timer-list.h"
#include "util/int-allocator.h"

namespace net {
namespace proxy {
namespace ares {

class Resolver {
public:
    struct Options {
        std::chrono::milliseconds query_timeout = std::chrono::seconds(1);
        std::chrono::nanoseconds cache_timeout = std::chrono::minutes(1);
    };

    Resolver(
        const any_io_executor &executor,
        Connector &connector,
        const Options &options);
    ~Resolver();

    using ResolveCallback =
        absl::AnyInvocable<void(
            std::error_code, const std::vector<address> &) &&>;
    void resolve(std::string_view host, ResolveCallback callback);

private:
    class Operation;

    void wait();

    static ares_socket_t asocket(
        int domain, int type, int protocol, void *user_data);
    static int aclose(ares_socket_t fd, void *user_data);
    static int aconnect(
        ares_socket_t fd, const sockaddr *addr, ares_socklen_t addr_len,
        void *user_data);
    static ares_ssize_t arecvfrom(
        ares_socket_t fd, void *buf, size_t buf_size, int flags,
        sockaddr *addr, ares_socklen_t *addr_len, void *user_data);
    static ares_ssize_t asendv(
        ares_socket_t fd, const iovec *data, int len, void *user_data);

    static const ares_socket_functions funcs_;

    any_io_executor executor_;
    proxy::Connector &connector_;
    ares_channel channel_ = nullptr;
    steady_timer wait_timer_;
    TimerList cache_timer_list_;
    absl::flat_hash_map<std::string, Operation *> operations_;
    absl::flat_hash_map<ares_socket_t, boost::intrusive_ptr<Socket>> sockets_;
    util::IntAllocator<ares_socket_t> socket_allocator_;
};

}  // namespace ares
}  // namespace proxy
}  // namespace net

#endif  // _NET_ARES_RESOLVER_H
