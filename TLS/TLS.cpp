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
    } catch(const ssl_error& e) {
        logger << e.what() << std::endl;
        tls_record r;
        r.type = 0x15;
        r.major_version = 0x03;
        r.minor_version = 0x03;
        r.contents = { static_cast<uint8_t>(e.m_l), static_cast<uint8_t>(e.m_d) };
        if(handshake_done) {
            file_assert(is_client_hello_done, "handshake done without hello");
            r = cipher_context->encrypt(r);
        }
        return {r.serialise(), status::closing };
    } catch(const std::out_of_range& e) {
        logger << e.what() << std::endl;
        return {{}, status::closed };
    }
    return output;
}

void TLS::handle_record(tls_record record, status_message& output) {
    logger << "TLS::handle_record()" <<std::endl;
    if (record.major_version != 3) {
        throw ssl_error("unsupported version", AlertLevel::fatal, AlertDescription::protocol_version);
    }
    if (record.contents.size() > 16384) {
        throw ssl_error("oversized record", AlertLevel::fatal, AlertDescription::record_overflow);
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
            throw ssl_error("bad record type", AlertLevel::fatal, AlertDescription::illegal_parameter);
            break;
    }
    
}
 
void TLS::client_handshake(ustring handshake_record, status_message& output) {
    logger << "TLS::client_handshake()" <<std::endl;
    switch (handshake_record.at(0)) {
        case static_cast<uint8_t>(HandshakeType::hello_request):
            throw ssl_error("hello_request not supported", AlertLevel::fatal, AlertDescription::handshake_failure);
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
            throw ssl_error("unsupported handshake record type", AlertLevel::fatal, AlertDescription::handshake_failure);
            break;
    }
}


void TLS::handle_client_hello(const ustring& hello, status_message& output) {
    logger << "TLS::handle_client_hello()" <<std::endl;
    // handshake header
    file_assert(hello.at(0) == 1, "handle_client_hello");

    
    size_t len = safe_asval(hello,1,3);
    if(len+4 != hello.size()) {
        throw ssl_error("bad hello", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    // client version
    if ( hello.at(4) != 3 or hello.at(5) != 3 ) {
        throw ssl_error("unsupported version handshake", AlertLevel::fatal, AlertDescription::handshake_failure);
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
    is_client_hello_done = true;
    
    idx += ciphers_len + 2;
    // compression
    if(hello.at(idx) != 1 and hello.at(idx + 1) != 0) {
        throw ssl_error("compression not supported", AlertLevel::fatal, AlertDescription::decompression_failure);
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
        throw ssl_error("bad extension", AlertLevel::fatal, AlertDescription::internal_error);
    }

    if(is_client_hello_done) {
        handshake_hasher->update(hello);
    } else {
        throw ssl_error("hello not done", AlertLevel::fatal, AlertDescription::internal_error);
    }
    
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
    hello_record.contents.append(m_server_random.cbegin(), m_server_random.cend());
    hello_record.contents.append({0}); // session ID
    ustring ciph;
    ciph.resize(2);
    write_int(cipher, &ciph[0], 2);
    hello_record.contents.append(ciph);
    hello_record.contents.append({0}); // no compression
    hello_record.contents.append({0x00, 0x05, 0xff, 0x01, 0x00, 0x01, 0x00}); // extensions
    write_int(hello_record.contents.size()-4, &hello_record.contents[1], 3);

    if(is_client_hello_done) {
        handshake_hasher->update(hello_record.contents);
    } else {
        throw ssl_error("hello not done", AlertLevel::fatal, AlertDescription::internal_error);
    }
    
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

    
    if(is_client_hello_done) {
        handshake_hasher->update(certificate_record.contents);
    } else {
        throw ssl_error("hello not done", AlertLevel::fatal, AlertDescription::internal_error);
    }
    
    return certificate_record;
}

tls_record TLS::server_key_exchange(){
    logger << "TLS::server_key_exchange()" << std::endl;
    randomgen.randgen(server_private_key_ephem.begin(), server_private_key_ephem.size());
    std::array<uint8_t,32> privrev;
    std::reverse_copy(server_private_key_ephem.cbegin(), server_private_key_ephem.cend(), privrev.begin());
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
    signed_empheral_key.append(curveInfo.cbegin(), curveInfo.cend());
    signed_empheral_key.append({static_cast<uint8_t>(pubkey_ephem.size())});
    signed_empheral_key.append(pubkey_ephem.cbegin(), pubkey_ephem.cend());

    
    if(!is_client_hello_done) {
        throw ssl_error("hello not done", AlertLevel::fatal, AlertDescription::internal_error);
    }
    
    auto hashctx = hasher_factory->clone();
    
    hashctx->update(m_client_random);
    hashctx->update(m_server_random);
    hashctx->update(signed_empheral_key);

    auto signature_digest_vec = hashctx->hash();
    file_assert(signature_digest_vec.size() == 32, "signature_digest_vec.size() == 32");
    std::array<uint8_t,32> signature_digest;
    std::copy(signature_digest_vec.cbegin(), signature_digest_vec.cend(), signature_digest.begin());
    
    
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
    
    if(!is_client_hello_done) {
        throw ssl_error("hello not done", AlertLevel::fatal, AlertDescription::internal_error);
    }
    
    handshake_hasher->update(record.contents);
    return record;
}

tls_record TLS::server_hello_done() {
    logger << "TLS::server_hello_done()" << std::endl;
    tls_record record;
    record.type = static_cast<uint8_t>(ContentType::Handshake);
    record.major_version = 3;
    record.minor_version = 3;
    record.contents = { static_cast<uint8_t>(HandshakeType::server_hello_done), 0x00, 0x00, 0x00 };
    
    if(!is_client_hello_done) {
        throw ssl_error("hello not done", AlertLevel::fatal, AlertDescription::internal_error);
    }
    
    handshake_hasher->update(record.contents);
    return record;
}

void TLS::handle_client_key_exchange(const ustring& key_exchange) {
    logger << "TLS::handle_client_key_exchange()" << std::endl;
    file_assert(key_exchange.at(0) == static_cast<uint8_t>(HandshakeType::client_key_exchange), "client key bad");
    
    const size_t len = safe_asval(key_exchange,1,3);
    const size_t keylen = safe_asval(key_exchange,4,1);
    if(len+4 != key_exchange.size() or len != keylen + 1) {
        throw ssl_error("bad key exchange", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    
    if(key_exchange.size() < 37) {
        throw ssl_error("bad public key", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    std::copy(&key_exchange[5], &key_exchange[37], client_public_key.begin());
    
    if(!is_client_hello_done) {
        throw ssl_error("hello not done", AlertLevel::fatal, AlertDescription::internal_error);
    }
    
    master_secret = make_master_secret(hasher_factory, server_private_key_ephem, client_public_key, m_server_random, m_client_random);
    
    // AES_256_CBC_SHA256 has the largest amount of material at 128 bytes
    ustring key_material = expand_master(master_secret, m_server_random, m_client_random, 128);
    
    
    cipher_context->set_key_material(key_material);
    handshake_hasher->update(key_exchange);
}

void TLS::client_change_cipher_spec(const ustring& change_message) {
    logger << "TLS::client_change_cipher_spec()" << std::endl;
    if(change_message.size() != 1 and change_message.at(0) != static_cast<uint8_t>(ChangeCipherSpec::change_cipher_spec)) {
        throw ssl_error("bad cipher spec", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    handshake_done = true;
}


void TLS::client_handshake_finished(const ustring& finish, status_message& output) {
    logger << "TLS::client_handshake_finished()" << std::endl;
    file_assert(finish.at(0) == static_cast<uint8_t>(HandshakeType::finished), "bad record type");
    const size_t len = safe_asval(finish,1,3);
    if(len != 12) {
        throw ssl_error("bad verification", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    const std::string seed_signed = "client finished";
    ustring seed;
    seed.append(seed_signed.cbegin(), seed_signed.cend());
    if(!is_client_hello_done) {
        throw ssl_error("hello not done", AlertLevel::fatal, AlertDescription::internal_error);
    }
    auto local_hasher = handshake_hasher->clone();
    auto handshake_hash = local_hasher->hash();
    seed.append(handshake_hash.cbegin(), handshake_hash.cend());

    const auto ctx = hmac(hasher_factory->clone(), master_secret);
    
    
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
        throw ssl_error("handshake verification failed", AlertLevel::fatal, AlertDescription::handshake_failure);
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
    seed.append(seedsi.cbegin(),seedsi.cend());
    
    
    if(!is_client_hello_done) {
        throw ssl_error("hello not done", AlertLevel::fatal, AlertDescription::internal_error);
    }
    
    
    auto local_hasher = handshake_hasher->clone(); // the others?
    auto handshake_hash = local_hasher->hash();
    file_assert(handshake_hash.size() == 32, "handshake hash size bad");
    seed.append(handshake_hash.begin(), handshake_hash.end());

    const auto ctx = hmac(hasher_factory->clone(), master_secret);
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
        throw ssl_error("Unwilling to respond on unencrypted channel", AlertLevel::fatal, AlertDescription::insufficient_security);
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
            file_assert(is_client_hello_done, "handshake finished without client hello");
            out = cipher_context->encrypt(std::move(out));
        } else {
            throw ssl_error("Unwilling to respond on unencrypted channel", AlertLevel::fatal, AlertDescription::insufficient_security);
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
        file_assert(is_client_hello_done, "handshake finished without client hello");
        close_record = cipher_context->encrypt(std::move(close_record));
    }
    output.m_response.append(close_record.serialise());
    output.m_status = status::closing;
}



bool TLS::client_alert(const ustring& alert_message, status_message& output) {
    logger << "TLS::client_alert()" << std::endl;
    if(alert_message.size() != 2) {
        throw ssl_error("bad alert", AlertLevel::fatal, AlertDescription::unexpected_message);
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
            logger << int(alert_message[0]) << " " << int(alert_message[1]) << " ";
            throw ssl_error("unsupported alert", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
}


void TLS::client_heartbeat(const ustring& heartbeat_message, status_message& output) {
    logger << "TLS::client_heartbeat()" << std::endl;
    if(heartbeat_message.size() != 1 or heartbeat_message[0] != 0x01) {
        throw ssl_error("bad heartbeat", AlertLevel::fatal, AlertDescription::access_denied);
    }
    
    tls_record heartbeat_record;
    heartbeat_record.type = static_cast<uint8_t>(ContentType::Heartbeat);
    heartbeat_record.major_version = 3;
    heartbeat_record.minor_version = 3;
    heartbeat_record.contents = {2};
    
    if(handshake_done) {
        file_assert(is_client_hello_done, "handshake finished without client hello");
        heartbeat_record = cipher_context->encrypt(std::move(heartbeat_record));
    }
    output.m_response.append(heartbeat_record.serialise());
}


std::array<uint8_t,48> TLS::make_master_secret(const std::unique_ptr<const hash_base>& hash_factory,
                                               std::array<uint8_t,32> server_private,
                                                std::array<uint8_t,32> client_public,
                                                std::array<uint8_t,32> server_random,
                                                std::array<uint8_t,32> client_random) {
    logger << "TLS::make_master_secret()" << std::endl;
    std::reverse(server_private.begin(), server_private.end());
    std::reverse(client_public.begin(), client_public.end());
    auto premaster_secret = fbw::curve25519::multiply(server_private, client_public);
    std::reverse(premaster_secret.begin(), premaster_secret.end());
    
    
    std::string seedsi = "master secret";
    ustring seed;
    seed.append(seedsi.cbegin(),seedsi.cend());
    seed.append(client_random.cbegin(), client_random.cend());
    seed.append(server_random.cbegin(), server_random.cend());
    
    
    
    const auto ctx = hmac(hash_factory->clone(), premaster_secret);
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
    std::copy(p1.cbegin(), p1.cend(), master_secret.begin());
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
            return x;
        }
        if(x == static_cast<uint16_t>(cipher_suites::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)) {
            cipher_context = std::make_unique<aes::AES_128_GCM_SHA256>();
            hasher_factory = std::make_unique<sha256>();
            handshake_hasher = hasher_factory->clone();
            return x;
        }
        
        
    }
    throw ssl_error("no supported ciphers", AlertLevel::fatal, AlertDescription::handshake_failure );
}

ustring TLS::expand_master(const std::array<unsigned char,48>& master,
                          const std::array<unsigned char,32>& server_random,
                          const std::array<unsigned char,32>& client_random, size_t len) const {

    ustring output;
    const std::string seed = "key expansion";
    ustring useed;
    useed.append(seed.cbegin(), seed.cend());
    useed.append(server_random.cbegin(), server_random.cend());
    useed.append(client_random.cbegin(), client_random.cend());
    auto a = useed;
    
    if(!is_client_hello_done) {
        throw ssl_error("expand_master bad", AlertLevel::fatal, AlertDescription::internal_error);
    }
    const auto ctx = hmac(hasher_factory->clone(), master);
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
    size_t record_size = safe_asval(input,3,2);
    if(input.size() < record_size + 5) {
        return std::nullopt;
    }
    out.contents = input.substr(5, record_size);
    input = input.substr(5 + record_size);
    return out;
}


void TLS::test_handshake() && {
    // test vectors found at https://tls.ulfheim.net/
    
    is_client_hello_done = true;
    
    hasher_factory = std::make_unique<const sha256>();
    
    server_private_key_ephem =  { 0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a,
        0x9b, 0x9c, 0x9d, 0x9e, 0x9f, 0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5, 0xa6, 0xa7, 0xa8, 0xa9,
        0xaa, 0xab, 0xac, 0xad, 0xae, 0xaf };

    m_client_random = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
        0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f };
    
    m_server_random = {0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a,
        0x7b, 0x7c, 0x7d, 0x7e, 0x7f, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8a,
        0x8b, 0x8c, 0x8d, 0x8e, 0x8f };
    
    client_public_key = {0x35, 0x80, 0x72, 0xd6, 0x36, 0x58, 0x80, 0xd1, 0xae, 0xea,
        0x32, 0x9a, 0xdf, 0x91, 0x21, 0x38, 0x38, 0x51, 0xed, 0x21, 0xa2, 0x8e, 0x3b, 0x75, 0xe9, 0x65, 0xd0,
        0xd2, 0xcd, 0x16, 0x62, 0x54 };

    auto master =  make_master_secret(hasher_factory, server_private_key_ephem,
                        client_public_key, m_server_random, m_client_random);
    
    auto key_material = expand_master(master, m_server_random, m_client_random, 128);
    // fine.
    
    cipher_context = std::make_unique<aes::AES_CBC_SHA>(16);
    cipher_context->set_key_material(key_material);
    
    
    tls_record ping;
    ping.type = 0x16;
    ping.major_version = 0x03;
    ping.minor_version = 0x03;
    ping.contents = {0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
        0x22, 0x7b, 0xc9, 0xba, 0x81, 0xef, 0x30, 0xf2, 0xa8, 0xa7, 0x8f, 0xf1, 0xdf, 0x50, 0x84, 0x4d, 0x58, 0x04,
        0xb7, 0xee, 0xb2, 0xe2, 0x14, 0xc3, 0x2b, 0x68, 0x92, 0xac, 0xa3, 0xdb, 0x7b, 0x78, 0x07, 0x7f, 0xdd, 0x90, 0x06,
        0x7c, 0x51, 0x6b, 0xac, 0xb3, 0xba, 0x90, 0xde, 0xdf, 0x72, 0x0f };

    auto output = cipher_context->decrypt(ping);
    const ustring answer_ping = {0x14, 0x00, 0x00, 0x0c, 0xcf, 0x91, 0x96, 0x26,
        0xf1, 0x36, 0x0c, 0x53, 0x6a, 0xaa, 0xd7, 0x3a };
    if(!std::equal(output.contents.begin(), output.contents.end(), answer_ping.begin(), answer_ping.end())) {
        logger << "failed decryption";
        std::terminate();
    }
}

};// namespace fbw
