//
//  http_connection.cpp
//  piformserver
//
//  Created by Frederick Benjamin Woodruff on 24/07/2021.
//

/*



 split out this file
 
 remove heap memory from handshake functions // profile
 // check bounds errors
 
 integrate the HTTP library.
 
 write an interesting website.
 
 implement a 'keep writing' function for the situation where the server is providing an
 infinite stream of data to the client and we still want to handle multiple clients
 implement a 'pipe-alert' function for the situation where a connection offloads work to another thread and we want this thread to go on.
 
 implement more cryptographic variants and alerts
 
 implement some post-quantum ciphers
*/

#include "TLS.hpp"

#include "x25519.hpp"
#include "secure_hash.hpp"
#include "secp256r1.hpp"
#include "PEMextract.hpp"
#include "TLS_enums.hpp"
#include "global.hpp"
#include "keccak.hpp"
#include "block_chain.hpp"
#include "galois_counter.hpp"

#include <iostream>
#include <iomanip>
#include <memory>
#include <string>
#include <fstream>
#include <sstream>
#include <random>
#include <algorithm>



namespace fbw {



std::optional<tls_record> try_extract_record(ustring& input);


// handler
status_message TLS::handle(ustring input) noexcept {
    logger << "TLS::handle()" <<std::endl;
    m_input.append(input);
    
    file_assert(input.size() < 20000, "TLS handle input size too much");
    
    status_message output;
    output.m_status = status::read_only;
    
    try {
        while(true) {
            auto record = try_extract_record(m_input);
            if(!record) {
                break;
            }
            handle_record(std::move(*record), output);
        }
    } catch(ssl_error e) {
        std::cerr << e.what() << std::endl;
        return {{}, status::closed };
    } catch(std::out_of_range e) {
        std::cerr << e.what() << std::endl;
        return {{}, status::closed };
    } catch(ssl_close_signal s) {
        std::cout << "TLS NOTIFY CLOSE" << std::endl;
        output.m_status = status::closing;
    }
    return output;
}

void TLS::handle_record(tls_record record, status_message& output) {
    logger << "TLS::handle_record()" <<std::endl;
    if (record.major_version != 3) {
        throw ssl_error("unsupported version"); // learn ssl errors
    }
    if (record.contents.size() > 16384) {
        throw ssl_error("oversized record");
    }
    
    if (handshake_done) {
        record = cipher_context->decrypt(std::move(record));
    }
    /*
    
    logger <<   "++++++++++++++++++++++\n";
    logger << "decrypted TLS:\n";
    logger << unsigned(record.type) << " " << unsigned(record.major_version) << " "
            << unsigned(record.minor_version) << " " << record.contents.size() << "\n";
    
    for(auto c : record.contents) {
        logger << std::hex << int(unsigned(c)) << " ";
    }
    logger << "\n++++++++++++++++++++++" << std::endl;
    */
    try {
        switch(record.type) {
            case static_cast<uint8_t>(ContentType::ChangeCipherSpec):
                client_change_cipher_spec(std::move(record.contents));
                break;
            case static_cast<uint8_t>(ContentType::Alert):
                client_alert(std::move(record.contents), output);
                break;
            case static_cast<uint8_t>(ContentType::Handshake):
                client_handshake(std::move(record.contents), output);
                break;
            case static_cast<uint8_t>(ContentType::Application):
                client_application_data(std::move(record.contents), output);
                break;
            case static_cast<uint8_t>(ContentType::Heartbeat):
                client_heartbeat(std::move(record.contents), output);
                break;
            default:
                throw ssl_error("bad record type");
                break;
        }
    } catch (std::out_of_range e) {
        throw ssl_error("bad sublength");
    }
}
 
void TLS::client_handshake(ustring handshake_record, status_message& output) {
    logger << "TLS::client_handshake()" <<std::endl;
    switch (handshake_record.at(0)) {
        case static_cast<uint8_t>(HandshakeType::hello_request):
            throw ssl_error("hello_request not supported");
        case static_cast<uint8_t>(HandshakeType::client_hello):
            handle_client_hello(std::move(handshake_record), output);
            break;
        case static_cast<uint8_t>(HandshakeType::client_key_exchange):
            handle_client_key_exchange(std::move(handshake_record));
            break;
        case static_cast<uint8_t>(HandshakeType::finished):
            client_handshake_finished(std::move(handshake_record), output);
            break;
        default:
            throw ssl_error("unsupported handshake record type");
            break;
    }
}


void TLS::handle_client_hello(const ustring& hello, status_message& output) {
    logger << "TLS::handle_client_hello()" <<std::endl;
    // handshake header
    file_assert(hello.at(0) == 1, "handle_client_hello");

    
    size_t len = safe_asval(hello,1,3);
    if(len+4 != hello.size()) {
        throw ssl_error("bad hello");
    }
    // client version
    if ( hello.at(4) != 3 or hello.at(5) != 3 ) {
        throw ssl_error("unsupported version handshake");
    }
    // client random
    std::copy(&hello.at(6), &hello.at(38), m_client_random.begin());
    // session ID
    size_t idx = 38;
    idx += safe_asval(hello, idx, 1) + 1;
    // cipher suites
    size_t ciphers_len = safe_asval(hello, idx, 2);
    hello.at(idx+ ciphers_len + 2);
    cipher = cipher_choice(hello.substr(idx+2, ciphers_len));
    
    idx += ciphers_len + 2;
    // compression
    if(hello.at(idx) != 1 and hello.at(idx + 1) != 0) {
        throw ssl_error("compression not supported");
    }
    idx += 2;
    // extensions
    ssize_t extensions_len = safe_asval(hello,idx,2);

    idx += 2;
    while(extensions_len > 0) {
        size_t extension_type = safe_asval(hello,idx,2);
        size_t extension_len = safe_asval(hello,idx+2,2);
        switch(extension_type) {
            case 0x000a:
            {
                break;
            }
            default:
                break;
        }
        idx += extension_len + 4;
        extensions_len -= extension_len + 4;
    }
    
    if(extensions_len != 0) {
        throw ssl_error("bad extension");
    }

    handshake_hasher->update(hello);
    
    output.m_response.append(server_hello().serialise());
    output.m_response.append(server_certificate().serialise());
    output.m_response.append(server_key_exchange().serialise());
    output.m_response.append(server_hello_done().serialise());
}

tls_record TLS::server_hello() {
    logger << "TLS::server_hello()" << std::endl;
    tls_record hello_record;
    hello_record.type = static_cast<uint8_t>(ContentType::Handshake);
    hello_record.major_version = 3;
    hello_record.minor_version = 3;
    hello_record.contents.reserve(49);
    hello_record.contents = {static_cast<uint8_t>(HandshakeType::server_hello), 0x00, 0x00, 0x00, 0x03, 0x03};
    
    randomgen.randgen(&m_server_random[0], 32);
    hello_record.contents.append(m_server_random.begin(), m_server_random.end());
    hello_record.contents.append({0}); // session ID
    ustring ciph;
    ciph.resize(2);
    write_int(cipher, &ciph[0], 2);
    hello_record.contents.append(ciph);
    hello_record.contents.append({0}); // no compression
    hello_record.contents.append({0x00, 0x05, 0xff, 0x01, 0x00, 0x01, 0x00}); // extensions
    write_int(hello_record.contents.size()-4, &hello_record.contents[1], 3);

    handshake_hasher->update(hello_record.contents);
    return hello_record;
}

tls_record TLS::server_certificate(){
    logger << "TLS::server_certificate()" << std::endl;
    tls_record certificate_record;
    certificate_record.type = static_cast<uint8_t>(ContentType::Handshake);
    certificate_record.major_version = 3;
    certificate_record.minor_version = 3;
    certificate_record.contents = {static_cast<uint8_t>(HandshakeType::certificate), 0,0,0, 0,0,0};
    
    const auto certs = der_cert_from_file(certificate_file);
    
    
    for (const auto& cert : certs) {
        ustring cert_header;
        cert_header.append({0,0,0});
        write_int(cert.size(), cert_header.data(), 3);
        certificate_record.contents.append(cert_header);
        certificate_record.contents.append(cert);
    }
    write_int(certificate_record.contents.size()-4, &certificate_record.contents[1], 3);
    write_int(certificate_record.contents.size()-7, &certificate_record.contents[4], 3);

    handshake_hasher->update(certificate_record.contents);
    return certificate_record;
}

tls_record TLS::server_key_exchange(){
    logger << "TLS::server_key_exchange()" << std::endl;
    randomgen.randgen(server_private_key_ephem.begin(), server_private_key_ephem.size());
    std::array<uint8_t,32> privrev;
    std::reverse_copy(server_private_key_ephem.begin(), server_private_key_ephem.end(), privrev.begin());
    std::array<uint8_t,32> pubkey_ephem = curve25519::base_multiply(privrev); // endianness could be wrong
    std::reverse(pubkey_ephem.begin(), pubkey_ephem.end());

    tls_record record;
    record.type = static_cast<uint8_t>(ContentType::Handshake);
    record.major_version = 3;
    record.minor_version = 3;
    record.contents.reserve(116);
    record.contents = { static_cast<uint8_t>(HandshakeType::server_key_exchange), 0x00, 0x00, 0x00 };
    std::array<uint8_t,3> curveInfo({static_cast<uint8_t>(ECCurveType::named_curve), 0x00, 0x00});
    write_int((size_t)NamedCurve::x25519, &curveInfo[1], 2);
    
    ustring signed_empheral_key;
    signed_empheral_key.append(curveInfo.begin(), curveInfo.end());
    signed_empheral_key.append({static_cast<uint8_t>(pubkey_ephem.size())});
    signed_empheral_key.append(pubkey_ephem.begin(), pubkey_ephem.end());

    auto hashctx = hasher_factory->clone();
    
    hashctx->update(m_client_random.data(), m_client_random.size());
    hashctx->update(m_server_random.data(), m_server_random.size());
    hashctx->update(signed_empheral_key.data(), signed_empheral_key.size());

    auto signature_digest_vec = hashctx->hash();
    file_assert(signature_digest_vec.size() == 32, "signature_digest_vec.size() == 32");
    std::array<uint8_t,32> signature_digest;
    std::copy(signature_digest_vec.begin(), signature_digest_vec.end(), signature_digest.begin());
    
    
    auto certificate_private = privkey_from_file(key_file);

    std::array<uint8_t,32> csrn;
    randomgen.randgen( csrn.begin(), csrn.size());
    ustring signature = secp256r1::DER_ECDSA(std::move(csrn), std::move(signature_digest), std::move(certificate_private));
    ustring sig_header ({static_cast<uint8_t>(HashAlgorithm::sha256),
        static_cast<uint8_t>(SignatureAlgorithm::ecdsa), 0x00, 0x00});
    write_int(signature.size(), &sig_header[2], 2);
    
    record.contents.append(signed_empheral_key);
    record.contents.append(sig_header);
    record.contents.append(signature);

    write_int(record.contents.size()-4, &record.contents[1], 3);
    handshake_hasher->update(record.contents.data(), record.contents.size());
    return record;
}

tls_record TLS::server_hello_done() {
    logger << "TLS::server_hello_done()" << std::endl;
    tls_record record;
    record.type = static_cast<uint8_t>(ContentType::Handshake);
    record.major_version = 3;
    record.minor_version = 3;
    record.contents = { static_cast<uint8_t>(HandshakeType::server_hello_done), 0x00, 0x00, 0x00 };
    handshake_hasher->update(record.contents);
    return record;
}

void TLS::handle_client_key_exchange(const ustring& key_exchange) {
    logger << "TLS::handle_client_key_exchange()" << std::endl;
    file_assert(key_exchange.at(0) == static_cast<uint8_t>(HandshakeType::client_key_exchange), "client key bad");
    
    const size_t len = safe_asval(key_exchange,1,3);
    const size_t keylen = safe_asval(key_exchange,4,1);
    if(len+4 != key_exchange.size() or len != keylen + 1) {
        throw ssl_error("bad key exchange");
    }
    
    if(key_exchange.size() < 37) {
        throw ssl_error("bad public key");
    }
    std::copy(&key_exchange[5], &key_exchange[37], client_public_key.begin());
    master_secret = make_master_secret(server_private_key_ephem, client_public_key, m_server_random, m_client_random);
    
    // AES_256_CBC_SHA256 has the largest amount of material at 128 bytes
    ustring key_material = expand_master(master_secret, m_server_random, m_client_random, 128);
    cipher_context->set_key_material(key_material);
    handshake_hasher->update(key_exchange);
}

void TLS::client_change_cipher_spec(const ustring& change_message) {
    if(change_message.size() != 1 and change_message.at(0) != static_cast<uint8_t>(ChangeCipherSpec::change_cipher_spec)) {
        throw ssl_error("bad cipher spec");
    }
    handshake_done = true;
}


void TLS::client_handshake_finished(const ustring& finish, status_message& output) {
    logger << "TLS::client_handshake_finished()" << std::endl;
    file_assert(finish.at(0) == static_cast<uint8_t>(HandshakeType::finished));
    const size_t len = safe_asval(finish,1,3);
    if(len != 12) {
        throw ssl_error("bad verification");
    }
    const std::string seed_signed = "client finished";
    ustring seed;
    seed.append(seed_signed.begin(), seed_signed.end());
    auto local_hasher = handshake_hasher->clone(); // placeholder
    auto handshake_hash = local_hasher->hash();
    seed.append(handshake_hash.begin(), handshake_hash.end());

    const auto ctx = hmac(hasher_factory->clone(), master_secret.data(), master_secret.size());
    
    
    auto ctx2 = ctx;
    auto a1 = ctx2
        .update(seed)
        .hash();
    auto p1 = (ctx2 = ctx)
        .update(a1)
        .update(seed)
        .hash();
    
    bool eq = true;
    for(int i = 0; i < 12; i ++) {
        if(finish.at(i+4) != p1.at(i)) {
            eq = false;
        }
    }
    if(eq == false) {
        throw ssl_error("handshake verification failed");
    }

    handshake_hasher->update(finish);
    server_change_cipher_spec(output);
    server_handshake_finished(output);
}

void TLS::server_change_cipher_spec(status_message& output) {
    logger << "TLS::server_change_cipher_spec()" << std::endl;
    ustring record ({static_cast<uint8_t>(ContentType::ChangeCipherSpec),
        0x03, 0x03, 0x00, 0x01, static_cast<uint8_t>(ChangeCipherSpec::change_cipher_spec)});
    output.m_response.append(record);
}

void TLS::server_handshake_finished(status_message& output) {
    logger << "TLS::server_handshake_finished()" << std::endl;
    tls_record out;
    out.type = static_cast<uint8_t>(ContentType::Handshake);
    out.major_version = 3;
    out.minor_version = 3;

    out.contents = {static_cast<uint8_t>(HandshakeType::finished), 0x00, 0x00, 0x0c};
    
    std::string seedsi = "server finished";
    ustring seed;
    seed.append(seedsi.begin(),seedsi.end());
    
    auto local_hasher = handshake_hasher->clone(); // the others?
    auto handshake_hash = local_hasher->hash();
    file_assert(handshake_hash.size() == 32, "handshake hash size bad");
    seed.append(handshake_hash.begin(), handshake_hash.end());

    const auto ctx = hmac(hasher_factory->clone(), &master_secret[0], master_secret.size());
    auto ctx2 = ctx;
    
    auto a1 = (ctx2 = ctx)
        .update(seed)
        .hash();

    auto p1 = (ctx2 = ctx)
        .update(a1)
        .update(seed)
        .hash();
    
    file_assert(p1.size() >= 12, "bad hash");
    out.contents.append(&p1[0], &p1[12]);

    if(handshake_done) {
        out = cipher_context->encrypt(std::move(out));
    } else {
        throw ssl_error("Unwilling to respond on unencrypted channel");
    }
    output.m_response.append(out.serialise());
}

void TLS::client_application_data(const ustring& application_data, status_message& output) {
    logger << "TLS::client_application_data()" << std::endl;
    const auto app_out = next->handle(application_data);
    output.m_status = app_out.m_status;
    int record_size = 1;
    for(size_t i = 0; i < app_out.m_response.size(); i += record_size) {
        // break up the http byte stream randomly
        record_size = std::clamp(int(randomgen.randgen64() % (7*app_out.m_response.size()/4)), 256, 10000);
        
        tls_record out;
        out.type = static_cast<uint8_t>(ContentType::Application);
        out.major_version = 3;
        out.minor_version = 3;
        out.contents.append(&app_out.m_response[i], &app_out.m_response[std::min(i+record_size, app_out.m_response.size())]);
        if(handshake_done) {
            out = cipher_context->encrypt(std::move(out));
        } else {
            throw ssl_error("Unwilling to respond on unencrypted channel");
        }
        output.m_response.append(out.serialise());
    }
}

void TLS::tls_notify_close(status_message& output) {
    logger << "TLS::tls_notify_close()" << std::endl;
    tls_record close_record;
    close_record.type = static_cast<uint8_t>(ContentType::Alert);
    close_record.major_version = 3;
    close_record.minor_version = 3;
    close_record.contents = {1,0};
    if(handshake_done) {
        close_record = cipher_context->encrypt(std::move(close_record));
    }
    output.m_response.append(close_record.serialise());
    output.m_status = status::closing;
}



bool TLS::client_alert(const ustring& alert_message, status_message& output) {
    logger << "TLS::client_alert()" << std::endl;
    if(alert_message.size() != 2) {
        throw ssl_error("bad alert");
    }
    switch(alert_message[0]) {
        case static_cast<uint8_t>(AlertLevel::warning):
            switch(alert_message[1]) {
                case static_cast<uint8_t>(AlertDescription::close_notify):

                    return true;
                    break;
                default:
                    goto flag;
            }
            break;
        default:
            flag:
            std::cout << int(alert_message[0]) << " " << int(alert_message[1]) << " ";
            throw ssl_error("unsupported alert");
    }
}


void TLS::client_heartbeat(const ustring& heartbeat_message, status_message& output) {
    logger << "TLS::client_heartbeat()" << std::endl;
    if(heartbeat_message.size() != 1 or heartbeat_message[0] != 0x01) {
        throw ssl_error("bad heartbeat");
    }
    
    tls_record heartbeat_record;
    heartbeat_record.type = static_cast<uint8_t>(ContentType::Heartbeat);
    heartbeat_record.major_version = 3;
    heartbeat_record.minor_version = 3;
    heartbeat_record.contents = {2};
    
    if(handshake_done) {
        heartbeat_record = cipher_context->encrypt(std::move(heartbeat_record));
    }
    output.m_response.append(heartbeat_record.serialise());
}


std::array<uint8_t,48> TLS::make_master_secret(std::array<uint8_t,32> server_private,
                                                std::array<uint8_t,32> client_public,
                                                std::array<uint8_t,32> server_random,
                                                std::array<uint8_t,32> client_random) const {
    logger << "TLS::make_master_secret()" << std::endl;
    std::reverse(server_private.begin(), server_private.end());
    std::reverse(client_public.begin(), client_public.end());
    auto premaster_secret = fbw::curve25519::multiply(server_private, client_public);
    std::reverse(premaster_secret.begin(), premaster_secret.end());
    
    
    std::string seedsi = "master secret";
    ustring seed;
    seed.append(seedsi.begin(),seedsi.end());
    seed.append(client_random.begin(), client_random.end());
    seed.append(server_random.begin(), server_random.end());
    
    const auto ctx = hmac(hasher_factory->clone(), premaster_secret.begin(), premaster_secret.size());
    auto ctx2 = ctx;
    auto a1 = (ctx2 = ctx)
                    .update(seed)
                    .hash();
    file_assert(a1.size() == 32, "master_secret a1.size()");
    auto a2 = (ctx2 = ctx)
                    .update(a1)
                    .hash();
    auto p1 = (ctx2 = ctx)
                    .update(a1)
                    .update(seed)
                    .hash();
    auto p2 = (ctx2 = ctx)
                    .update(a2)
                    .update(seed)
                    .hash();

    std::array<uint8_t,48> master_secret;
    std::copy(p1.begin(), p1.end(), master_secret.begin());
    std::copy(&*p2.begin(), &p2[16], &master_secret[32]);
    
    return master_secret;
}


unsigned short TLS::cipher_choice(const ustring& s) {
    logger << "TLS::cipher_choice()" << std::endl;
    for(size_t i = 0; i < s.size(); i += 2) {
        uint16_t x = safe_asval(s, i, 2);
        
        if (x == static_cast<uint16_t>(cipher_suites::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)) {
            cipher_context = std::make_unique<aes::AES_CBC_SHA>(16);
            hasher_factory = std::make_unique<sha256>();
            handshake_hasher = hasher_factory->clone();
            // cloneable should maybe be an interface class
            return x;
        }
        /*
        if(x == static_cast<uint16_t>(cipher_suites::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)) {
            cipher_context = std::make_unique<aes::AES_128_GCM_SHA256>();
            hasher_factory = std::make_unique<sha256>();
            handshake_hasher = hasher_factory->clone();
            return x;
        }
         */
        
    }
    throw ssl_error("no supported ciphers");
}

ustring TLS::expand_master(const std::array<unsigned char,48>& master,
                          const std::array<unsigned char,32>& server_random,
                          const std::array<unsigned char,32>& client_random, size_t len) const {

    ustring output;
    const std::string seed = "key expansion";
    ustring useed;
    useed.append(seed.begin(), seed.end());
    useed.append(server_random.begin(), server_random.end());
    useed.append(client_random.begin(), client_random.end());
    auto a = useed;
    const auto ctx = hmac(hasher_factory->clone(), master.begin(), master.size());
    auto ctx2 = ctx;
    while(output.size() < len) {
        ctx2 = ctx;
        ctx2.update(a);
        auto ou = ctx2.hash();
        a.clear();
        a.append(ou);
        ctx2 = ctx;
        ctx2.update(a)
            .update(useed);
        ou = ctx2.hash();
        output.append(ou);
    }
    output.resize(len);
    return output;
}





std::optional<tls_record> try_extract_record(ustring& input) {
    if (input.size() < 5) {
        return std::nullopt;
    }
    tls_record out;
    out.type = input[0];
    out.major_version = input[1];
    out.minor_version = input[2];
    uint16_t record_size = safe_asval(input,3,2);
    if(input.size() < record_size + 5) {
        return std::nullopt;
    }
    out.contents = input.substr(5, record_size);
    input = input.substr(5 + record_size);
    return out;
}

};// namespace fbw
