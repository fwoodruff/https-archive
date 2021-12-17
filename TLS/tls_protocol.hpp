//
//  http_connection.hpp
//  troubleshooter
//
//  Created by Frederick Benjamin Woodruff on 25/11/2021.
//

#ifndef tls_connection_hpp
#define tls_connection_hpp

#include "connection.hpp"
#include "blockchain.hpp"
#include "global.hpp"
#include "secure_hash.hpp"
#include "receiver.hpp"

#include <array>
#include <string>

namespace fbw {

class tls_connection : public fbw::connection_base {
    
    ustring input;
    std::array<uint8_t,32> m_client_random;
    std::array<uint8_t,32> m_server_random;
    // session ID
    unsigned short cipher;
    
    bool handshake_done = false;
    std::array<uint8_t,32> client_public_key;
    std::array<uint8_t,32> server_private_key_ephem;
    
    std::unique_ptr<hash_base> handshake_hasher;
    
    std::array<uint8_t,48> master_secret;

    
    std::unique_ptr<cipher_base> cipher_context;
    
    std::unique_ptr<const hash_base> hasher_factory;
    
    
    bool handle_record(tls_record record);
    void client_handshake(ustring handshake_message);
    void client_change_cipher_spec(const ustring& change_message);
    bool client_alert(const ustring& alert_message);
    void client_heartbeat(const ustring& heartbeat_message);
    
    void handle_client_hello(const ustring& hello);
    [[nodiscard]] tls_record server_hello();
    [[nodiscard]] tls_record server_certificate();
    [[nodiscard]] tls_record server_key_exchange();
    [[nodiscard]] tls_record server_hello_done();
    void handle_client_key_exchange(const ustring& key_exchange);
    void client_handshake_finished(const ustring& ciphertext);
    void server_change_cipher_spec();
    void server_handshake_finished();
    
    [[nodiscard]] ustring expand_master(const std::array<unsigned char,48>& master,
                          const std::array<unsigned char,32>& server_random,
                          const std::array<unsigned char,32>& client_random, size_t len) const;
    [[nodiscard]] std::array<uint8_t,48> make_master_secret(std::array<uint8_t,32> server_private,
                                              std::array<uint8_t,32> client_public,
                                              std::array<uint8_t,32> server_random,
                                              std::array<uint8_t,32> client_random) const;
    
    unsigned short cipher_choice(const ustring& s);
    
    void client_application_data(const ustring& data);
    
    
    
    //void server_application_data(const ustring& data_stream);

    ustring incoming_application_data;
public:
    //static std::unique_ptr<fbw::connection_base> ctor_my();
    void handle_connection() noexcept final override;
    
    void  read_app(std::string& chars);
    void write_app(const std::string& chars);
    void tls_notify_close();
    
    virtual void handle_session_data() = 0;
};


} // namespace fbw

#endif /* tls_connection_hpp */
