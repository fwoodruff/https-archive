//
//  TLS.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 24/07/2021.
//

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
#include "chacha20poly1305.hpp"

#include <iostream>
#include <iomanip>
#include <memory>
#include <string>
#include <fstream>
#include <sstream>
#include <random>
#include <algorithm>


constexpr size_t TLS_RECORD_SIZE = (1u << 14) - 5;

namespace fbw {

std::optional<tls_record> try_extract_record(ustring& input);


status_message TLS::handle(ustring input) noexcept {
    assert(input.empty() ==  more_to_send);
    assert(input.size() < 20000);
    
    if(more_to_send) {
        auto out = handle_flush();
        return out;
    } else {
        auto out = handle_input(std::move(input));
        return out;
    }
}


status_message TLS::handle_input(ustring input) noexcept {
    assert(!input.empty());
    m_input.append(input);

    status_message output {.m_status = status::read_write};
    
    try {
        while(true) {
            auto record = try_extract_record(m_input);
            if(!record) {
                break;
            }
            handle_record(std::move(*record), output);
            if(more_to_send) {
                break;
            }
        }
    } catch(const ssl_error& e) {
        auto r = tls_record(ContentType::Alert);
        r.m_contents = { static_cast<uint8_t>(e.m_l), static_cast<uint8_t>(e.m_d) };
        if(is_change_cipher_spec_done) {
            assert(cipher_context != nullptr);
            assert(is_client_hello_done);
            r = cipher_context->encrypt(r);
        }
        auto str = r.serialise();
        return {str, status::closing };
    } catch(const std::out_of_range& e) {
        next.reset();
        return {{}, status::closed };
    } catch (const std::logic_error& e) {
        std::cerr << "from logic error\n";
        return {{}, status::closed };
    } catch(...) {
        assert(false);
    }
    return output;
}

status_message TLS::handle_flush() noexcept {
    auto msg = generate_packet(1); // around 10kb per batch
    return msg;
}

void TLS::handle_record(tls_record record, status_message& output) {
    if (record.get_major_version() != 3) {
        throw ssl_error("unsupported version", AlertLevel::fatal, AlertDescription::protocol_version);
    }
    if (record.m_contents.size() > TLS_RECORD_SIZE) {
        throw ssl_error("oversized record", AlertLevel::fatal, AlertDescription::record_overflow);
    }

    if (is_change_cipher_spec_done) {
        record = cipher_context->decrypt(std::move(record));
    }

    switch(record.get_type()) {
        case static_cast<uint8_t>(ContentType::ChangeCipherSpec):
            client_change_cipher_spec(std::move(record.m_contents));
            break;
        case static_cast<uint8_t>(ContentType::Alert):
            client_alert(std::move(record.m_contents), output);
            break;
        case static_cast<uint8_t>(ContentType::Handshake):
            client_handshake(std::move(record.m_contents), output);
            break;
        case static_cast<uint8_t>(ContentType::Application):
            client_application_data(std::move(record.m_contents), output);
            break;
        case static_cast<uint8_t>(ContentType::Heartbeat):
            client_heartbeat(std::move(record.m_contents), output);
            break;
        default:
            throw ssl_error("bad record type", AlertLevel::fatal, AlertDescription::illegal_parameter);
            break;
    }
}
 
void TLS::client_handshake(ustring handshake_record, status_message& output) {
    assert(handshake_record.size() <= TLS_RECORD_SIZE);
    
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
    assert(hello.size() >= 1 and hello[0] == 1);
    
    
    if (is_client_hello_done == true or
        is_client_key_exchange_done == true or
        is_change_cipher_spec_done == true or
        is_client_handshake_finished_done == true) {
        
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    
    
    size_t len = try_bigend_read(hello,1,3);
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
    idx += try_bigend_read(hello, idx, 1) + 1;
    // cipher suites
    size_t ciphers_len = try_bigend_read(hello, idx, 2);
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
    ssize_t extensions_len = try_bigend_read(hello,idx,2);

    idx += 2;
    while(extensions_len > 0) {
        size_t extension_type = try_bigend_read(hello, idx, 2);
        size_t extension_len = try_bigend_read(hello, idx + 2, 2);
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
    auto hello_record = tls_record(ContentType::Handshake);
    
    hello_record.m_contents.reserve(49);
    hello_record.m_contents = {static_cast<uint8_t>(HandshakeType::server_hello), 0x00, 0x00, 0x00, 0x03, 0x03};
    
    randomgen.randgen(m_server_random.data(), 32);
    hello_record.m_contents.append(m_server_random.cbegin(), m_server_random.cend());
    hello_record.m_contents.append({0}); // session ID
    ustring ciph;
    ciph.resize(2);
    checked_bigend_write(cipher, ciph, 0, 2);
    hello_record.m_contents.append(ciph);
    hello_record.m_contents.append({0}); // no compression
    hello_record.m_contents.append({0x00, 0x05, 0xff, 0x01, 0x00, 0x01, 0x00}); // extensions
    assert(hello_record.m_contents.size() >= 4);
    checked_bigend_write(hello_record.m_contents.size()-4, hello_record.m_contents, 1, 3);

    if(is_client_hello_done) {
        handshake_hasher->update(hello_record.m_contents);
    } else {
        throw ssl_error("hello not done", AlertLevel::fatal, AlertDescription::internal_error);
    }
    
    return hello_record;
}

tls_record TLS::server_certificate() {
    tls_record certificate_record(ContentType::Handshake);
    certificate_record.m_contents = {static_cast<uint8_t>(HandshakeType::certificate), 0,0,0, 0,0,0};
    
    const auto certs = der_cert_from_file(certificate_file);

    for (const auto& cert : certs) {
        ustring cert_header;
        cert_header.append({0, 0, 0});
        checked_bigend_write(cert.size(), cert_header, 0, 3);
        certificate_record.m_contents.append(cert_header);
        certificate_record.m_contents.append(cert);
    }

    assert(certificate_record.m_contents.size() >= 7);
    checked_bigend_write(certificate_record.m_contents.size() - 4, certificate_record.m_contents, 1, 3);
    checked_bigend_write(certificate_record.m_contents.size() - 7, certificate_record.m_contents, 4, 3);

    if(is_client_hello_done) {
        handshake_hasher->update(certificate_record.m_contents);
    } else {
        throw ssl_error("hello not done", AlertLevel::fatal, AlertDescription::internal_error);
    }
    
    return certificate_record;
}

tls_record TLS::server_key_exchange() {
    randomgen.randgen(server_private_key_ephem.begin(), server_private_key_ephem.size());
    std::array<uint8_t,32> privrev;
    std::reverse_copy(server_private_key_ephem.cbegin(), server_private_key_ephem.cend(), privrev.begin());
    std::array<uint8_t,32> pubkey_ephem = curve25519::base_multiply(privrev);
    std::reverse(pubkey_ephem.begin(), pubkey_ephem.end());

    tls_record record(ContentType::Handshake);

    record.m_contents.reserve(116);
    record.m_contents = { static_cast<uint8_t>(HandshakeType::server_key_exchange), 0x00, 0x00, 0x00 };
    std::array<uint8_t,3> curveInfo({static_cast<uint8_t>(ECCurveType::named_curve), 0x00, 0x00});
    
    checked_bigend_write(static_cast<size_t>(NamedCurve::x25519), curveInfo, 1, 2);
    
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
    assert(signature_digest_vec.size() == 32);
    std::array<uint8_t,32> signature_digest;
    std::copy(signature_digest_vec.cbegin(), signature_digest_vec.cend(), signature_digest.begin());
    
    
    auto certificate_private = privkey_from_file(key_file);

    std::array<uint8_t,32> csrn;
    randomgen.randgen( csrn.begin(), csrn.size());
    ustring signature = secp256r1::DER_ECDSA(std::move(csrn), std::move(signature_digest), std::move(certificate_private));
    ustring sig_header ({static_cast<uint8_t>(HashAlgorithm::sha256),
        static_cast<uint8_t>(SignatureAlgorithm::ecdsa), 0x00, 0x00});
    
    checked_bigend_write(signature.size(), sig_header, 2, 2);
    
    record.m_contents.append(signed_empheral_key);
    record.m_contents.append(sig_header);
    record.m_contents.append(signature);

    assert(record.m_contents.size() >= 4);
    checked_bigend_write(record.m_contents.size()-4, record.m_contents, 1, 3);
    
    if(!is_client_hello_done) {
        throw ssl_error("hello not done", AlertLevel::fatal, AlertDescription::internal_error);
    }
    
    handshake_hasher->update(record.m_contents);
    return record;
}

tls_record TLS::server_hello_done() {
    tls_record record(ContentType::Handshake);
    record.m_contents = { static_cast<uint8_t>(HandshakeType::server_hello_done), 0x00, 0x00, 0x00 };
    
    if(!is_client_hello_done) {
        throw ssl_error("hello not done", AlertLevel::fatal, AlertDescription::internal_error);
    }
    
    handshake_hasher->update(record.m_contents);
    return record;
}

void TLS::handle_client_key_exchange(const ustring& key_exchange) {
    assert(key_exchange.size() >= 1);
    assert(key_exchange[0] == static_cast<uint8_t>(HandshakeType::client_key_exchange));
    
    if (is_client_hello_done == false or
        is_client_key_exchange_done == true or
        is_change_cipher_spec_done == true or
        is_client_handshake_finished_done == true) {
        
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    
    const size_t len = try_bigend_read(key_exchange,1,3);
    const size_t keylen = try_bigend_read(key_exchange,4,1);
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
    
    is_client_key_exchange_done = true;
}

void TLS::client_change_cipher_spec(const ustring& change_message) {

    if (is_client_hello_done == false or
        is_client_key_exchange_done == false or
        is_change_cipher_spec_done == true or
        is_client_handshake_finished_done == true) {
        
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    
    if(change_message.size() != 1 and change_message.at(0) != static_cast<uint8_t>(ChangeCipherSpec::change_cipher_spec)) {
        throw ssl_error("bad cipher spec", AlertLevel::fatal, AlertDescription::handshake_failure);
    }
    
    is_change_cipher_spec_done = true;
}


void TLS::client_handshake_finished(const ustring& finish, status_message& output) {
    finish.at(0);
    assert(finish[0] == static_cast<uint8_t>(HandshakeType::finished));
    
    if (is_client_hello_done == false or
        is_client_key_exchange_done == false or
        is_change_cipher_spec_done == false or
        is_client_handshake_finished_done == true) {
        
        throw ssl_error("bad handshake message ordering", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    
    
    
    const size_t len = try_bigend_read(finish,1,3);
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
    
    is_client_handshake_finished_done = true;
}

void TLS::server_change_cipher_spec(status_message& output) {
    ustring record ({static_cast<uint8_t>(ContentType::ChangeCipherSpec),
        0x03, 0x03, 0x00, 0x01, static_cast<uint8_t>(ChangeCipherSpec::change_cipher_spec)});
    output.m_response.append(record);
}

void TLS::server_handshake_finished(status_message& output) {
    tls_record out(ContentType::Handshake);
    out.m_contents = { static_cast<uint8_t>(HandshakeType::finished), 0x00, 0x00, 0x0c };
    
    const std::string SERVER_HANDSHAKE_SEED = "server finished";
    ustring seed;
    seed.append(SERVER_HANDSHAKE_SEED.cbegin(),SERVER_HANDSHAKE_SEED.cend());
    
    if(!is_client_hello_done) {
        throw ssl_error("hello not done", AlertLevel::fatal, AlertDescription::internal_error);
    }
    auto local_hasher = handshake_hasher->clone(); // the others?
    auto handshake_hash = local_hasher->hash();
    assert(handshake_hash.size() == 32);
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
    
    assert(p1.size() >= 12);
    out.m_contents.append(&p1[0], &p1[12]);
    if(is_change_cipher_spec_done) {
        out = cipher_context->encrypt(std::move(out));
    } else {
        throw ssl_error("Unwilling to respond on unencrypted channel", AlertLevel::fatal, AlertDescription::insufficient_security);
    }
    output.m_response.append(out.serialise());
}

/*
 This is a generator and uses the following class arguments as its state
 bool more_to_send
 size_t send_byte_idx
 status_message app_out
 
 The purpose is to batch process large requests to avoid denial of service
 */
status_message TLS::generate_packet(int num_records) {
    assert(more_to_send == true);
    status_message output {};
    
    for(int i = 0; i < num_records; i++) {
        size_t small_record_size = std::clamp(size_t(randomgen.randgen64() % TLS_RECORD_SIZE), size_t(1), TLS_RECORD_SIZE);
        size_t record_size = (randomgen.randgen64() % 10 != 0) ? TLS_RECORD_SIZE : small_record_size;
        
        assert(app_out.m_response.size() >= send_byte_idx);
        record_size = std::min(record_size, app_out.m_response.size() - send_byte_idx);
        
        if(record_size < 1) {
            throw ssl_error("null record", AlertLevel::fatal, AlertDescription::unexpected_message);
        }
        assert(app_out.m_response.size() >= send_byte_idx+record_size);
        
        tls_record out(ContentType::Application);
        out.m_contents.append(&app_out.m_response[send_byte_idx],
                              &app_out.m_response[send_byte_idx+record_size]);
        out = cipher_context->encrypt(std::move(out));
        output.m_response.append(out.serialise());
        
        send_byte_idx += record_size;
        
        if(send_byte_idx == app_out.m_response.size()) {
            more_to_send = false;
            send_byte_idx = 0;
            output.m_status = app_out.m_status;
            app_out.m_response.clear();
            break;
        } else {
            output.m_status = status::flush;
        }
    }
    return output;
}

void TLS::client_application_data(const ustring& application_data, status_message& output) {
    if (is_client_hello_done == false or
        is_client_key_exchange_done == false or
        is_change_cipher_spec_done == false or
        is_client_handshake_finished_done == false) {
        
        throw ssl_error("handshake already done", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
    
    assert(app_out.m_response.empty());
    assert( output.m_response.empty());
    
    app_out = next->handle(application_data);
    send_byte_idx = 0;
    more_to_send = true;

    output = TLS::generate_packet(10); // files over 100kb might not be returned in one go.
}

void TLS::tls_notify_close(status_message& output) {
    tls_record close_record( ContentType::Alert);

    close_record.m_contents = {1,0};
    if(is_change_cipher_spec_done) {
        assert(is_client_hello_done);
        close_record = cipher_context->encrypt(std::move(close_record));
    }
    output.m_response.append(close_record.serialise());
    output.m_status = status::closing;
    next.reset();
}

bool TLS::client_alert(const ustring& alert_message, status_message& output) {
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
                    (void)output;
                    goto flag;
            }
            break;
        default:
            flag:
            throw ssl_error("unsupported alert", AlertLevel::fatal, AlertDescription::unexpected_message);
    }
}

void TLS::client_heartbeat(const ustring& heartbeat_message, status_message& output) {
    if(heartbeat_message.size() != 1 or heartbeat_message[0] != 0x01) {
        throw ssl_error("heartbleed", AlertLevel::fatal, AlertDescription::access_denied);
    }
    tls_record heartbeat_record( ContentType::Heartbeat);
    heartbeat_record.m_contents = {2};
    if(is_change_cipher_spec_done) {
        assert(is_client_hello_done);
        heartbeat_record = cipher_context->encrypt(std::move(heartbeat_record));
    }
    output.m_response.append(heartbeat_record.serialise());
}

std::array<uint8_t,48> TLS::make_master_secret(const std::unique_ptr<const hash_base>& hash_factory,
                                               std::array<uint8_t,32> server_private,
                                                std::array<uint8_t,32> client_public,
                                                std::array<uint8_t,32> server_random,
                                                std::array<uint8_t,32> client_random) {
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
    assert(a1.size() == 32);
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
    for(size_t i = 0; i < s.size(); i += 2) {
        uint16_t x = try_bigend_read(s, i, 2);
        if (x == static_cast<uint16_t>(cipher_suites::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256)) {
            cipher_context = std::make_unique<cha::ChaCha20_Poly1305>();
            hasher_factory = std::make_unique<sha256>();
            handshake_hasher = hasher_factory->clone();
            return x;
        }
    }
    for(size_t i = 0; i < s.size(); i += 2) {
        uint16_t x = try_bigend_read(s, i, 2);
        if(x == static_cast<uint16_t>(cipher_suites::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256)) {
            cipher_context = std::make_unique<aes::AES_128_GCM_SHA256>();
            hasher_factory = std::make_unique<sha256>();
            handshake_hasher = hasher_factory->clone();
            return x;
        }
        if (x == static_cast<uint16_t>(cipher_suites::TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA)) {
            cipher_context = std::make_unique<aes::AES_CBC_SHA>();
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
    tls_record out(static_cast<ContentType>(input[0]), input[1], input[2] );

    size_t record_size = try_bigend_read(input,3,2);
    if(input.size() < record_size + 5) {
        return std::nullopt;
    }
    out.m_contents = input.substr(5, record_size);
    input = input.substr(5 + record_size);
    return out;
}

};// namespace fbw
