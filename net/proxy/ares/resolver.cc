#include "net/proxy/ares/resolver.h"

#include <chrono>
#include <memory>
#include <string>

namespace net {
namespace proxy {
namespace ares {

const ares_socket_functions Resolver::funcs_ =
    {asocket, aclose, aconnect, arecvfrom, asendv};

Resolver::Resolver(
    const any_io_executor &executor,
    Connector &connector,
    const Options &options)
    : executor_(executor),
      connector_(connector),
      wait_timer_(executor_) {
    ares_options ares_options;
    ares_options.timeout = options.timeout.count();
    if (ares_init_options(&channel_, &ares_options, ARES_OPT_TIMEOUTMS) !=
        ARES_SUCCESS) {
        abort();
    }
    ares_set_socket_functions(channel_, &funcs_, this);    
}

Resolver::~Resolver() {
    ares_destroy(channel_);
}

struct ResolveOperation {
    Resolver &resolver;
    Resolver::ResolveCallback callback;
};

void Resolver::resolve(std::string_view host, ResolveCallback callback) {
    auto *operation = new ResolveOperation{*this, std::move(callback)};
    ares_getaddrinfo(
        channel_, std::string(host).c_str(), nullptr, nullptr,
        resolve_finish, operation);
    wait();
}

void Resolver::resolve_finish(void *arg, int status, int, ares_addrinfo *res) {
    std::unique_ptr<ResolveOperation> operation(
        reinterpret_cast<ResolveOperation *>(arg));
    auto &resolver = operation->resolver;
    post(resolver.executor_, [&resolver]() { resolver.wait(); });
    if (status) {
        std::move(operation->callback)(
            make_error_code(std::errc::bad_address), {});
        ares_freeaddrinfo(res);
        return;
    }
    std::vector<address> addresses;
    for (ares_addrinfo_node *node = res->nodes; node; node = node->ai_next) {
        if (node->ai_family == AF_INET) {
            if (node->ai_addrlen < sizeof(sockaddr_in)) {
                continue;
            }
            auto *addr4 = reinterpret_cast<sockaddr_in *>(node->ai_addr);
            addresses.push_back(address_v4(ntohl(addr4->sin_addr.s_addr)));
        } else if (node->ai_family == AF_INET6) {
            if (node->ai_addrlen < sizeof(sockaddr_in6)) {
                continue;
            }
            auto *addr6 = reinterpret_cast<sockaddr_in6 *>(node->ai_addr);
            address_v6::bytes_type bytes;
            memcpy(bytes.data(), addr6->sin6_addr.s6_addr, 16);
            addresses.push_back(address_v6(bytes));
        }
    }
    ares_freeaddrinfo(res);
    std::move(operation->callback)({}, std::move(addresses));
}

void Resolver::wait() {
    timeval tv_buf;
    timeval *tv = ares_timeout(channel_, nullptr, &tv_buf);
    if (!tv) {
        wait_timer_.cancel();
        return;
    }
    wait_timer_.expires_after(std::chrono::seconds(tv->tv_sec) +
                              std::chrono::milliseconds(1) +
                              std::chrono::microseconds(tv->tv_usec));
    wait_timer_.async_wait([this](std::error_code ec) {
        if (ec) {
            return;
        }
        ares_process_fd(channel_, ARES_SOCKET_BAD, ARES_SOCKET_BAD);
        wait();
    });
}

ares_socket_t Resolver::asocket(
    int domain, int type, int protocol, void *user_data) {
    auto *resolver = reinterpret_cast<Resolver *>(user_data);
    ares_socket_t fd = resolver->socket_allocator_.allocate();
    boost::intrusive_ptr<Socket> socket;
    switch (type) {
    case SOCK_STREAM:
        socket = new TcpSocket(
            resolver->channel_, fd, resolver->executor_, resolver->connector_);
        break;
    case SOCK_DGRAM:
        socket = new UdpSocket(
            resolver->channel_, fd, resolver->executor_, resolver->connector_);
        break;
    default:
        resolver->socket_allocator_.deallocate(fd);
        return -1;
    }
    resolver->sockets_.emplace(fd, std::move(socket));
    return fd;
}

int Resolver::aclose(ares_socket_t fd, void *user_data) {
    auto *resolver = reinterpret_cast<Resolver *>(user_data);
    auto iter = resolver->sockets_.find(fd);
    if (iter == resolver->sockets_.end()) {
        return -1;
    }
    iter->second->close();
    resolver->sockets_.erase(iter);
    resolver->socket_allocator_.deallocate(fd);
    return 0;
}

int Resolver::aconnect(
    ares_socket_t fd, const sockaddr *addr, ares_socklen_t addr_len,
    void *user_data) {
    auto *resolver = reinterpret_cast<Resolver *>(user_data);
    auto iter = resolver->sockets_.find(fd);
    if (iter == resolver->sockets_.end()) {
        return -1;
    }
    return iter->second->connect(addr, addr_len);
}

ares_ssize_t Resolver::arecvfrom(
    ares_socket_t fd, void *buf, size_t buf_size, int flags,
    sockaddr *addr, ares_socklen_t *addr_len, void *user_data) {
    auto *resolver = reinterpret_cast<Resolver *>(user_data);
    auto iter = resolver->sockets_.find(fd);
    if (iter == resolver->sockets_.end()) {
        return -1;
    }
    return iter->second->recvfrom(buf, buf_size, flags, addr, addr_len);
}

ares_ssize_t Resolver::asendv(
    ares_socket_t fd, const iovec *data, int len, void *user_data) {
    auto *resolver = reinterpret_cast<Resolver *>(user_data);
    auto iter = resolver->sockets_.find(fd);
    if (iter == resolver->sockets_.end()) {
        return -1;
    }
    return iter->second->sendv(data, len);
}

}  // namespace ares
}  // namespace proxy
}  // namespace net
