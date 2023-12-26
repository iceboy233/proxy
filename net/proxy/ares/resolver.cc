#include "net/proxy/ares/resolver.h"

#include <algorithm>
#include <chrono>
#include <memory>
#include <optional>
#include <string>

#include "net/proxy/ares/error-category.h"

namespace net {
namespace proxy {
namespace ares {

class Resolver::Operation {
public:
    Operation(Resolver &resolver, std::string_view host);
    ~Operation();

    void add_callback(ResolveCallback callback);
    void start();

private:
    static void finish(void *arg, int status, int, ares_addrinfo *ai);
    void parse(int status, ares_addrinfo *ai);
    void cache();

    Resolver &resolver_;
    std::string host_;
    std::vector<ResolveCallback> callbacks_;
    bool finished_ = false;
    std::error_code ec_;
    std::vector<address> addresses_;
    std::optional<TimerList::Timer> timer_;
};

const ares_socket_functions Resolver::funcs_ =
    {asocket, aclose, aconnect, arecvfrom, asendv};

Resolver::Resolver(
    const any_io_executor &executor,
    Connector &connector,
    const Options &options)
    : executor_(executor),
      connector_(connector),
      wait_timer_(executor_),
      cache_timer_list_(executor_, options.cache_timeout),
      address_family_(options.address_family) {
    if (ares_library_init(ARES_LIB_INIT_ALL) != ARES_SUCCESS) {
        abort();
    }
    ares_options ares_options;
    ares_options.timeout = options.query_timeout.count();
    if (ares_init_options(&channel_, &ares_options, ARES_OPT_TIMEOUTMS) !=
        ARES_SUCCESS) {
        abort();
    }
    ares_set_socket_functions(channel_, &funcs_, this);
    if (!options.servers.empty()) {
        set_servers(options.servers);
    }
}

Resolver::~Resolver() {
    ares_destroy(channel_);
    ares_library_cleanup();
}

void Resolver::resolve(std::string_view host, ResolveCallback callback) {
    auto iter = operations_.find(host);
    if (iter != operations_.end()) {
        iter->second->add_callback(std::move(callback));
        return;
    }
    auto *operation = new Operation(*this, host);
    operation->add_callback(std::move(callback));
    operation->start();
    wait();
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

void Resolver::set_servers(absl::Span<const Endpoint> servers) {
    auto nodes = std::make_unique<ares_addr_port_node[]>(servers.size());
    for (size_t i = 0; i < servers.size(); ++i) {
        nodes[i].next = i + 1 < servers.size() ? &nodes[i + 1] : nullptr;
        const address &address = servers[i].address();
        if (address.is_v4()) {
            nodes[i].family = AF_INET;
            auto address_bytes = address.to_v4().to_bytes();
            static_assert(address_bytes.size() == 4);
            memcpy(&nodes[i].addr.addr4, address_bytes.data(), 4);
        } else {
            nodes[i].family = AF_INET6;
            auto address_bytes = address.to_v6().to_bytes();
            static_assert(address_bytes.size() == 16);
            memcpy(&nodes[i].addr.addr6, address_bytes.data(), 16);
        }
        nodes[i].udp_port = servers[i].port();
        nodes[i].tcp_port = servers[i].port();
    }
    if (ares_set_servers_ports(channel_, nodes.get()) != ARES_SUCCESS) {
        abort();
    }
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

Resolver::Operation::Operation(Resolver &resolver, std::string_view host)
    : resolver_(resolver), host_(host) {
    resolver_.operations_.emplace(host_, this);
}

Resolver::Operation::~Operation() {
    resolver_.operations_.erase(host_);
    if (resolver_.operations_.empty()) {
        resolver_.wait_timer_.cancel();
    }
}

void Resolver::Operation::add_callback(ResolveCallback callback) {
    if (finished_) {
        std::move(callback)(ec_, addresses_);
        return;
    }
    callbacks_.push_back(std::move(callback));
}

void Resolver::Operation::start() {
    ares_addrinfo_hints hints = {};
    switch (resolver_.address_family_) {
    case AddressFamily::v4_only:
        hints.ai_family = AF_INET;
        break;
    case AddressFamily::v6_only:
        hints.ai_family = AF_INET6;
        break;
    default:
        hints.ai_family = AF_UNSPEC;
        break;
    }
    ares_getaddrinfo(
        resolver_.channel_, host_.c_str(), nullptr, &hints, finish, this);
}

void Resolver::Operation::finish(
    void *arg, int status, int, ares_addrinfo *ai) {
    auto *operation = reinterpret_cast<Operation *>(arg);
    operation->finished_ = true;
    operation->parse(status, ai);
    ares_freeaddrinfo(ai);
    auto callbacks = std::move(operation->callbacks_);
    operation->callbacks_.clear();
    for (auto &callback : callbacks) {
        std::move(callback)(operation->ec_, operation->addresses_);
    }
    if (operation->ec_) {
        delete operation;
        return;
    }
    operation->cache();
}

void Resolver::Operation::parse(int status, ares_addrinfo *ai) {
    if (status != ARES_SUCCESS) {
        ec_ = std::error_code(status, error_category());
        return;
    }
    for (ares_addrinfo_node *node = ai->nodes; node; node = node->ai_next) {
        if (node->ai_family == AF_INET) {
            if (node->ai_addrlen < sizeof(sockaddr_in)) {
                continue;
            }
            auto *addr4 = reinterpret_cast<sockaddr_in *>(node->ai_addr);
            address_v4::bytes_type bytes;
            memcpy(bytes.data(), &addr4->sin_addr, 4);
            addresses_.push_back(address_v4(bytes));
        } else if (node->ai_family == AF_INET6) {
            if (node->ai_addrlen < sizeof(sockaddr_in6)) {
                continue;
            }
            auto *addr6 = reinterpret_cast<sockaddr_in6 *>(node->ai_addr);
            address_v6::bytes_type bytes;
            memcpy(bytes.data(), &addr6->sin6_addr, 16);
            addresses_.push_back(address_v6(bytes));
        }
    }
    switch (resolver_.address_family_) {
    case AddressFamily::prefer_v4:
        std::stable_partition(
            addresses_.begin(), addresses_.end(),
            [](const address &address) { return address.is_v4(); });
        break;
    case AddressFamily::prefer_v6:
        std::stable_partition(
            addresses_.begin(), addresses_.end(),
            [](const address &address) { return address.is_v6(); });
        break;
    default:
        break;
    }    
}

void Resolver::Operation::cache() {
    timer_.emplace(resolver_.cache_timer_list_, [this]() { delete this; });
}

}  // namespace ares
}  // namespace proxy
}  // namespace net
