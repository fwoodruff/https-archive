//
//  block_chain.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 12/12/2021.
//

#ifndef CBC_mode_hpp
#define CBC_mode_hpp

#include "AES.hpp"
#include "cipher_base.hpp"
#include "global.hpp"

#include <vector>
#include <stdio.h>

namespace fbw::aes {

class AES_CBC_SHA : public cipher_base {
private:
    roundkey m_server_write_round_keys;
    roundkey m_client_write_round_keys;
    std::array<uint8_t, 20> m_server_MAC_key;
    std::array<uint8_t, 20> m_client_MAC_key;

    size_t m_key_size;
    uint64_t m_seqno_server;
    uint64_t seqno_client;
    
public:
    AES_CBC_SHA(size_t key_size);
    
    void set_key_material(ustring material) override;
    tls_record encrypt(tls_record record) override;
    tls_record decrypt(tls_record record) override;
};

} // namespace fbw

#endif /* CBC_mode_hpp */
