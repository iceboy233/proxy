#ifndef _NET_ENDPOINT_H
#define _NET_ENDPOINT_H

#include <cstdint>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

#include "absl/strings/numbers.h"
#include "absl/strings/str_cat.h"
#include "absl/strings/str_split.h"
#include "net/asio.h"

namespace net {

template <typename AddressT>
class EndpointBase {
public:
    EndpointBase() = default;
    EndpointBase(const AddressT &address, uint16_t port)
        : address_(address), port_(port) {}

    const AddressT &address() const { return address_; }
    void set_address(const AddressT &address) { address_ = address; }
    uint16_t port() const { return port_; }
    void set_port(uint16_t port) { port_ = port; }

    operator tcp::endpoint() const { return {address_, port_}; }
    operator udp::endpoint() const { return {address_, port_}; }

    static std::optional<EndpointBase<AddressT>> from_string(
        std::string_view string);
    std::string to_string() const;

private:
    AddressT address_;
    uint16_t port_;
};

template <typename AddressT>
std::optional<EndpointBase<AddressT>> EndpointBase<AddressT>::from_string(
    std::string_view string) {
    std::pair<std::string_view, std::string_view> pair =
        absl::StrSplit(string, ':');
    boost::system::error_code ec;
    auto address = make_address(pair.first, ec);
    if (ec) {
        return std::nullopt;
    }
    // TODO(iceboy): Parse uint16_t natively.
    uint32_t port32;
    if (!absl::SimpleAtoi(pair.second, &port32) ||
        port32 > std::numeric_limits<uint16_t>::max()) {
        return std::nullopt;
    }
    return EndpointBase<AddressT>(address, static_cast<uint16_t>(port32));
}

template <typename AddressT>
std::string EndpointBase<AddressT>::to_string() const {
    return absl::StrCat(address_.to_string(), ":", port_);
}

using Endpoint = EndpointBase<address>;
using EndpointV4 = EndpointBase<address_v4>;
using EndpointV6 = EndpointBase<address_v6>;

template <typename AddressT>
bool AbslParseFlag(
    absl::string_view in, EndpointBase<AddressT> *out, std::string *error) {
    auto address_or = EndpointBase<AddressT>::from_string(in);
    if (!address_or) {
        return false;
    }
    *out = *address_or;
    return true;
}

template <typename AddressT>
std::string AbslUnparseFlag(const EndpointBase<AddressT> &in) {
    return in.to_string();
}

}  // namespace net

#endif  // _NET_ENDPOINT_H
