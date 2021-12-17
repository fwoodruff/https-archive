//
//  CBC_mode.hpp
//  basichttps
//
//  Created by Frederick Benjamin Woodruff on 12/12/2021.
//

#ifndef CBC_mode_hpp
#define CBC_mode_hpp

#include "AES.hpp"
#include "cipher_base.hpp"
#include "global.hpp"

#include <stdio.h>

namespace fbw::aes {

class AES_128_CBC_context : public cipher_base {
    roundkey<128> server_write_round_keys;
    roundkey<128> client_write_round_keys;
    std::array<uint8_t, 20> server_MAC_key;
    std::array<uint8_t, 20> client_MAC_key;
    
    uint64_t seqno_server = 0;
    uint64_t seqno_client = 0;
    
public:
    AES_128_CBC_context() = default;
    
    void set_key_material(ustring material) override;
    tls_record encrypt(tls_record record) override;
    tls_record decrypt(tls_record record) override;
};

} // namespace fbw

#endif /* CBC_mode_hpp */
