//
//  chacha20poly1305.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 12/02/2022.
//

#ifndef chacha20poly1305_hpp
#define chacha20poly1305_hpp

#include <stdio.h>

#include "cipher_base.hpp"

#include <vector>
#include <array>

namespace fbw::cha {

class ChaCha20_Poly1305 : public cipher_base {
//private:
public:
    
    std::array<uint8_t, 32> client_write_key;
    std::array<uint8_t, 32> server_write_key;
    
    std::array<uint8_t, 12> client_implicit_write_IV;
    std::array<uint8_t, 12> server_implicit_write_IV;
    
    uint64_t seqno_server = 0;
    uint64_t seqno_client = 0;
    
public:
    ChaCha20_Poly1305() = default;
    
    void set_key_material(ustring material) override;
    tls_record encrypt(tls_record record) override;
    tls_record decrypt(tls_record record) override;
    
    
};

} // namespace fbw


#endif /* chacha20poly1305_hpp */
