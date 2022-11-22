#include "net/proxy/shadowsocks/pre-shared-key.h"

#include <openssl/md5.h>

namespace net {
namespace proxy {
namespace shadowsocks {

bool PreSharedKey::init(const Method &method, std::string_view password) {
    method_ = &method;
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, password.data(), password.size());
    MD5_Final(&material_[0], &ctx);
    if (size() > 16) {
        MD5_Init(&ctx);
        MD5_Update(&ctx, &material_[0], 16);
        MD5_Update(&ctx, password.data(), password.size());
        MD5_Final(&material_[16], &ctx);
    }
    return true;
}

}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net
