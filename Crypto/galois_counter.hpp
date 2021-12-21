//
//  galois_counter.hpp
//  https_server
//
//  Created by Frederick Benjamin Woodruff on 17/12/2021.
//

#ifndef galois_counter_hpp
#define galois_counter_hpp

#include <stdio.h>
#include "cipher_base.hpp"
#include "AES.hpp"

#include <vector>
#include <array>

namespace fbw::aes {

/*
 enum class cipher_suites : uint16_t {
     TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca8,
     TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256 = 0xcca9,
     TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 = 0xc02f,
     TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 = 0xc030,
     TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256 = 0xc02b,
     TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384 = 0xc02c,
     TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA = 0xc013,
     TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA = 0xc009,
     TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA = 0xc014,
     TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA = 0xc00a,
     TLS_RSA_WITH_AES_128_GCM_SHA256 = 0x009c,
     TLS_RSA_WITH_AES_256_GCM_SHA384 = 0x009d,
     TLS_RSA_WITH_AES_128_CBC_SHA = 0x002f,
     TLS_RSA_WITH_AES_256_CBC_SHA = 0x0035,
     TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA = 0xc012,
     TLS_RSA_WITH_3DES_EDE_CBC_SHA = 0x000a
 };
 */

class AES_128_GCM_SHA256 : public cipher_base {
    
    roundkey client_write_round_keys;
    roundkey server_write_round_keys;
    
    ustring client_explicit_write_IV;
    ustring server_explicit_write_IV;
    
    uint64_t seqno_server = 0;
    uint64_t seqno_client = 0;
    
public:
    AES_128_GCM_SHA256() = default;
    
    void set_key_material(ustring material) override;
    tls_record encrypt(tls_record record) override;
    tls_record decrypt(tls_record record) override;
    
};
 
void test();

} // namespace fbw

#endif /* galois_counter_hpp */
