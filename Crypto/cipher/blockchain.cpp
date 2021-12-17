//
//  CBC_mode.cpp
//  basichttps
//
//  Created by Frederick Benjamin Woodruff on 12/12/2021.
//

#include "blockchain.hpp"
#include "secure_hash.hpp"
#include "AES.hpp"
#include "global.hpp"
#include "keccak.hpp"

#include <iostream>
#include <iomanip>

namespace fbw::aes {




void AES_128_CBC_context::set_key_material(ustring expanded_master)  {
    assert(expanded_master.size() >= 104);

    std::array<unsigned char,16> client_write_key;
    std::array<unsigned char,16> server_write_key;
    
    std::copy(&expanded_master[0], &expanded_master[20], client_MAC_key.begin());
    std::copy(&expanded_master[20], &expanded_master[40], server_MAC_key.begin());
    std::copy(&expanded_master[40], &expanded_master[56], client_write_key.begin());
    std::copy(&expanded_master[56], &expanded_master[72], server_write_key.begin());
    //std::copy(&expanded_master[72], &expanded_master[88], client_write_IV.begin());
    //std::copy(&expanded_master[88], &expanded_master[104], server_write_IV.begin());
    
    client_write_round_keys = aes_key_schedule(client_write_key); // retest?
    server_write_round_keys = aes_key_schedule(server_write_key);
}


ustring pad_message(ustring message) {
    const auto blocksize = 16;
    const auto padmax = 256;
    assert(padmax > blocksize and padmax % blocksize == 0);
    
    // randomises the padding length
    const auto min_padded_message_size = ((message.size() / blocksize)+1)* blocksize;
    const auto max_padded_message_size = ((message.size() / padmax)+1)* padmax;
    auto randval = randomgen.randgen64();
    const auto padded_message_size = min_padded_message_size +
                (randval*blocksize) % (blocksize+max_padded_message_size-min_padded_message_size);

    const auto padding_checked = padded_message_size - message.size();
    assert(padded_message_size > message.size());
    assert(padding_checked < padmax);
    const uint8_t padding = padding_checked;
    message.append(padding, padding-1);
    assert(message.size() % blocksize == 0);
    return message;
}


tls_record AES_128_CBC_context::encrypt(tls_record record) {

    auto ctx = hmac(std::make_unique<sha1>() , &*server_MAC_key.begin(),server_MAC_key.size() );

    std::array<uint8_t,13> sequence;
    write_int(seqno_server, &sequence[0], 8);
    seqno_server++;
    sequence[8] = record.type;
    sequence[9] = record.major_version;
    sequence[10] = record.minor_version;
    write_int(record.contents.size(),&sequence[11], 2);
    ctx.update(sequence.begin(), sequence.size());
    ctx.update((uint8_t*)&record.contents[0], record.contents.size());
    auto machash = std::move(ctx).hash();
    
    record.contents.append(machash.begin(),machash.end());
    
    
    std::array<uint8_t, 16> record_IV {};
    randomgen.randgen(&record_IV[0], record_IV.size());

    record.contents = pad_message(std::move(record.contents));
    
    ustring out;
    out.append(record_IV.begin(),record_IV.end());
    auto in_block = record_IV;
    for(size_t i = 0; i < record.contents.size(); i += 16) {
        std::transform(in_block.begin(), in_block.end(), &record.contents[i], in_block.begin(), std::bit_xor<uint8_t>());
        auto out_block = aes_encrypt(in_block, server_write_round_keys);
        out.append(out_block.begin(),out_block.end());
        in_block = out_block;
    }
    record.contents = std::move(out);
    return record;
}

tls_record AES_128_CBC_context::decrypt(tls_record record) {
    if(record.contents.size() % 16 != 0) {
        throw ssl_error("bad encrypted record length");
    }
    if(record.contents.size() < 32) {
        record.contents = {};
        return record;
    }
    ustring plaintext;
    std::array<uint8_t, 16> record_IV {};
    std::copy((uint8_t*)&*record.contents.begin(),(uint8_t*)&record.contents[16], record_IV.begin() );
    
    
    const auto blocksize = record_IV.size();
    std::array<uint8_t,16> xor_block = record_IV;
    for(size_t i = 16; i < record.contents.size(); i += blocksize) {
        std::array<uint8_t,16> in_block {};
        std::copy(&record.contents[i], &record.contents[i+blocksize], in_block.begin());
        auto plainxor = aes_decrypt(in_block, client_write_round_keys);
        
        std::transform(plainxor.begin(), plainxor.end(), xor_block.begin(), plainxor.begin(), std::bit_xor<uint8_t>());
        xor_block = in_block;
        
        plaintext.append(plainxor.begin(),plainxor.end());
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

    
    std::array<uint8_t, 20> mac_calc;
    std::copy(plaintext.rbegin(), plaintext.rbegin() + 20, mac_calc.rbegin());
    plaintext.resize(plaintext.size() - mac_calc.size());

    auto ctx = hmac(std::make_unique<sha1>(), &*client_MAC_key.begin(),client_MAC_key.size() );
    std::array<uint8_t,13> mac_hash_header;
    write_int(seqno_client, &mac_hash_header[0], 8);
    mac_hash_header[8] = record.type;
    mac_hash_header[9] = record.major_version;
    mac_hash_header[10] = record.minor_version;

    seqno_client++;
    write_int(plaintext.size(),&mac_hash_header[11], 2);

    ctx.update(mac_hash_header.data(), mac_hash_header.size());
    ctx.update(plaintext.data(), plaintext.size());
    auto machash = std::move(ctx).hash();
    
    if(!std::equal(mac_calc.begin(), mac_calc.end(), machash.begin())) {
        throw ssl_error("bad client MAC");
    }
    record.contents = std::move(plaintext);
    return record;
}

} // namespace fbw::aes
