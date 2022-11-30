#include "net/proxy/shadowsocks/pre-shared-key.h"

#include <openssl/md5.h>
#include <string>

#include "absl/strings/escaping.h"
#include "base/logging.h"

namespace net {
namespace proxy {
namespace shadowsocks {

bool PreSharedKey::init(const Method &method, std::string_view password) {
    method_ = &method;
    if (method_->is_spec_2022()) {
        std::string material;
        if (!absl::Base64Unescape(password, &material)) {
            LOG(error) << "base64 decode failed";
            return false;
        }
        if (material.size() != size()) {
            LOG(error) << "invalid key size";
            return false;
        }
        memcpy(material_.data(), material.data(), material.size());
    } else {
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
    }
    return true;
}

}  // namespace shadowsocks
}  // namespace proxy
}  // namespace net
