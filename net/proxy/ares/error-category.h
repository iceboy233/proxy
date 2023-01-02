#ifndef _NET_PROXY_ARES_ERROR_CATEGORY_H
#define _NET_PROXY_ARES_ERROR_CATEGORY_H

#include <system_error>

namespace net {
namespace proxy {
namespace ares {

const std::error_category &error_category();

}  // namespace ares
}  // namespace proxy
}  // namespace net

#endif  // _NET_PROXY_ARES_ERROR_CATEGORY_H
