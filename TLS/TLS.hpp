//
//  http_connection.hpp
//  troubleshooter
//
//  Created by Frederick Benjamin Woodruff on 25/11/2021.
//

#ifndef tls_hpp
#define tls_hpp

#include "connection.hpp"
#include "block_chain.hpp"
#include "global.hpp"
#include "secure_hash.hpp"
#include "receiver.hpp"

#include <array>
#include <string>

namespace fbw {

class TLS final : public receiver {
    
    ustring m_input;
    std::array<uint8_t,32> m_client_random;
    std::array<uint8_t,32> m_server_random;
    // session ID
    unsigned short cipher;
    
    bool handshake_done = false;
    bool is_client_hello_done = false;
    
    
    std::array<uint8_t,32> client_public_key;
    std::array<uint8_t,32> server_private_key_ephem;
    
    std::unique_ptr<hash_base> handshake_hasher;
    
    std::array<uint8_t,48> master_secret;

    
    std::unique_ptr<cipher_base> cipher_context;
    
    std::unique_ptr<const hash_base> hasher_factory;
    
    
    void handle_record(tls_record record, status_message& output);
    void client_handshake(ustring handshake_message, status_message& output);
    void client_change_cipher_spec(const ustring& change_message);
    bool client_alert(const ustring& alert_message, status_message& output);
    void client_heartbeat(const ustring& heartbeat_message, status_message& output);
    
    void handle_client_hello(const ustring& hello, status_message& output);
    [[nodiscard]] tls_record server_hello();
    [[nodiscard]] tls_record server_certificate();
    [[nodiscard]] tls_record server_key_exchange();
    [[nodiscard]] tls_record server_hello_done();
    void handle_client_key_exchange(const ustring& key_exchange);
    void client_handshake_finished(const ustring& ciphertext, status_message& output);
    void server_change_cipher_spec(status_message& output);
    void server_handshake_finished(status_message& output);
    
    [[nodiscard]] ustring expand_master(const std::array<unsigned char,48>& master,
                          const std::array<unsigned char,32>& server_random,
                          const std::array<unsigned char,32>& client_random, size_t len) const;
    
    
    unsigned short cipher_choice(const ustring& s);
    
    void client_application_data(const ustring& data, status_message& output);

    void tls_notify_close(status_message& output); // keep this?
    
    [[nodiscard]] static std::array<uint8_t,48> make_master_secret(const std::unique_ptr<const hash_base>& hasher,
                                                            std::array<uint8_t,32> server_private,
                                              std::array<uint8_t,32> client_public,
                                              std::array<uint8_t,32> server_random,
                                              std::array<uint8_t,32> client_random);
public:
    
    
    status_message handle(ustring) noexcept override;
    
    void test_handshake() && ;
    
};


} // namespace fbw

#endif /* tls_connection_hpp */
