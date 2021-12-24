//
//  CBC.cpp
//  https_server
//
//  Created by Frederick Benjamin Woodruff on 12/12/2021.
//

#include "block_chain.hpp"
#include "secure_hash.hpp"
#include "AES.hpp"
#include "global.hpp"
#include "keccak.hpp"

#include <algorithm>
#include <iostream>
#include <iomanip>

namespace fbw::aes {

AES_CBC_SHA::AES_CBC_SHA(size_t key_size) : server_write_round_keys({}),
                                            client_write_round_keys({}),
                                            server_MAC_key({}),
                                            client_MAC_key({}),
                                            m_key_size(key_size),
                                            seqno_server(0),
                                            seqno_client(0) { }


void AES_CBC_SHA::set_key_material(ustring expanded_master)  {
    file_assert(expanded_master.size() >= 104, "insufficient material in set_key");

    auto client_write_key = std::vector<uint8_t>(16,0);
    auto server_write_key = std::vector<uint8_t>(16,0);
    
    auto it = expanded_master.begin();

    
    
    
    std::copy_n(it, client_MAC_key.size(), client_MAC_key.begin());
    it += client_MAC_key.size();
    std::copy_n(it, server_MAC_key.size(), server_MAC_key.begin());
    it += server_MAC_key.size();
    std::copy_n(it, client_write_key.size(), client_write_key.begin());
    it += client_write_key.size();
    std::copy_n(it, server_write_key.size(), server_write_key.begin());
    it += server_write_key.size();
    
    
    client_write_round_keys = aes_key_schedule(client_write_key);
    server_write_round_keys = aes_key_schedule(server_write_key);
}


ustring pad_message(ustring message) {
    const auto blocksize = 16;
    const auto padmax = 256;
    
    file_assert(padmax > blocksize and padmax % blocksize == 0, "misaligned padding");
    
    // randomises the padding length
    const auto min_padded_message_size = ((message.size() / blocksize)+1)* blocksize;
    const auto max_padded_message_size = ((message.size() / padmax)+1)* padmax;
    auto randval = randomgen.randgen64();
    const auto padded_message_size = min_padded_message_size +
                (randval*blocksize) % (blocksize+max_padded_message_size-min_padded_message_size);

    const auto padding_checked = padded_message_size - message.size();
    
    file_assert(padded_message_size > message.size(), "padded_message_size > message.size()");
    file_assert(padding_checked < padmax, "padding_checked < padmax"); // this has actually fired
    const uint8_t padding = padding_checked;
    message.append(padding, padding-1);
    file_assert(message.size() % blocksize == 0, "message.size() % blocksize == 0");
    return message;
}


tls_record AES_CBC_SHA::encrypt(tls_record record) {

    auto ctx = hmac(std::make_unique<sha1>(), server_MAC_key );

    std::array<uint8_t,13> sequence {};
    write_int(seqno_server, &sequence[0], 8);
    seqno_server++;
    sequence[8] = record.type;
    sequence[9] = record.major_version;
    sequence[10] = record.minor_version;
    write_int(record.contents.size(),&sequence[11], 2);
    ctx.update(sequence);
    ctx.update(record.contents);
    auto machash = std::move(ctx).hash();
    
    record.contents.append(machash);
    
    std::array<uint8_t, 16> record_IV {};
    randomgen.randgen(&record_IV[0], record_IV.size());

    record.contents = pad_message(std::move(record.contents));
    
    ustring out;
    out.append(record_IV.cbegin(),record_IV.cend());
    auto in_block = record_IV;
    for(size_t i = 0; i < record.contents.size(); i += 16) {
        std::transform(in_block.cbegin(), in_block.cend(), &record.contents[i], in_block.begin(), std::bit_xor<uint8_t>());
        auto out_block = aes_encrypt(in_block, server_write_round_keys);
        out.append(out_block.cbegin(),out_block.cend());
        in_block = out_block;
    }
    record.contents = std::move(out);
    return record;
}

tls_record AES_CBC_SHA::decrypt(tls_record record) {
    
    
    if(record.contents.size() % 16 != 0) {
        throw ssl_error("bad encrypted record length");
    }
    if(record.contents.size() < 32) {
        record.contents = {};
        return record;
    }
    ustring plaintext;
    std::array<uint8_t, 16> record_IV {};
    constexpr auto blocksize = record_IV.size();
    
    file_assert(record.contents.size() >= 16);
    std::copy(&*record.contents.begin(),&record.contents[blocksize], record_IV.begin() );

    
    auto xor_block = record_IV;
    
    for(size_t i = blocksize; i < record.contents.size(); i += blocksize) {
        std::array<uint8_t,blocksize> in_block {};
        std::copy(&record.contents[i], &record.contents[i+blocksize], in_block.begin());

        auto plainxor = aes_decrypt(in_block, client_write_round_keys);

        std::transform(plainxor.cbegin(), plainxor.cend(), xor_block.cbegin(), plainxor.begin(), std::bit_xor<uint8_t>());
        xor_block = in_block;

        plaintext.append(plainxor.cbegin(),plainxor.cend());
    }
    int siz = plaintext[plaintext.size()-1];
    if(siz+1+client_MAC_key.size() > plaintext.size()) {
        throw ssl_error("bad client padding length");
    }
    for(int i = 0; i < siz+1; i++) {
        if(plaintext[plaintext.size()-1-i] != siz) {
            throw ssl_error("bad client padding");
        }
    }

    plaintext.resize(plaintext.size()-siz-1);

    
    std::array<uint8_t, 20> mac_calc {};
    std::copy(plaintext.crbegin(), plaintext.crbegin() + 20, mac_calc.rbegin());
    plaintext.resize(plaintext.size() - mac_calc.size());

    auto ctx = hmac(std::make_unique<sha1>(), client_MAC_key);
    std::array<uint8_t,13> mac_hash_header {};
    write_int(seqno_client, &mac_hash_header[0], 8);
    mac_hash_header[8] = record.type;
    mac_hash_header[9] = record.major_version;
    mac_hash_header[10] = record.minor_version;

    seqno_client++;
    write_int(plaintext.size(),&mac_hash_header[11], 2);

    ctx.update(mac_hash_header);
    ctx.update(plaintext);
    auto machash = std::move(ctx).hash();
    
    if(!std::equal(mac_calc.cbegin(), mac_calc.cend(), machash.cbegin())) {
        throw ssl_error("bad client MAC");
    }
    record.contents = std::move(plaintext);
    return record;
}



} // namespace fbw::aes
