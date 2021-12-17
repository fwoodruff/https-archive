//
//  cipher_base.hpp
//  https_server
//
//  Created by Frederick Benjamin Woodruff on 17/12/2021.
//

#ifndef cipher_base_hpp
#define cipher_base_hpp

#include "global.hpp"

#include <cstdio>

namespace fbw {
class cipher_base {
public:
    virtual void set_key_material(ustring material) = 0;
    virtual tls_record encrypt(tls_record record) = 0;
    virtual tls_record decrypt(tls_record record) = 0;
    virtual ~cipher_base() noexcept = default;
};
}

#endif /* cipher_base_hpp */
