//
//  chacha20poly1305.cpp
//  https_server
//
//  Created by Frederick Benjamin Woodruff on 12/02/2022.
//

#include "chacha20poly1305.hpp"
#include "global.hpp"
#include "keccak.hpp"
#include "bignum.hpp"

#include <algorithm>
#include <array>

namespace fbw::cha {

constexpr uint32_t ROT32(uint32_t x, int shift) {
    return (x << shift) | (x >> (32 - shift));
}

void chacha_quarter_round(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a += *b; *d ^= *a; *d = ROT32(*d, 16);
    *c += *d; *b ^= *c; *b = ROT32(*b, 12);
    *a += *b; *d ^= *a; *d = ROT32(*d, 8);
    *c += *d; *b ^= *c; *b = ROT32(*b, 7);
}


inline void write32_bigend(uint32_t x, uint8_t* s) noexcept {
    for(short i = 0; i < 4; i++) {
        s[i] = static_cast<uint8_t>(x) & 0xffU;
        x>>=8;
    }
}

[[nodiscard]] inline uint32_t asval_bigend(uint8_t const* s) {
    uint32_t len = 0;
    for(int i = 3; i >= 0; i--) {
        len <<= 8;
        len |= s[i];
    }
    return len;
}

std::array<uint8_t, 64> chacha20(const std::array<uint8_t, 32>& key, const std::array<uint8_t, 12>& nonce, uint32_t block_count) {
    
    std::array<uint32_t, 16> state {0};
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    
    for(int i = 0; i < 8; i++) {
        state[i+4] = asval_bigend(&key[i*4]);
    }
    
    state[12] = block_count;
    for(int i = 0; i < 3; i++) {
        state[i+13] = asval_bigend(&nonce[i*4]);
    }
    
    
    
    const auto state_orig = state;
    for(int j = 0; j < 10; j++) {
        for(int i = 0; i < 4; i++) {
            chacha_quarter_round(&state[i], &state[i+4], &state[i+8], &state[i+12]);
        }
        for(int i = 0; i < 4; i++) {
            chacha_quarter_round(&state[i], &state[4 + ((i+1) % 4)], &state[8 + ((i+2) % 4)], &state[12 + ((i+3) % 4)]);
        }
    }
    std::array<uint8_t, 64> out;
    for(int i = 0; i < 16; i++) {
        uint32_t statei = state[i] + state_orig[i];
        write32_bigend(statei, &out[i*4]);
    }
    return out;
}

ustring chacha20_encrypt(   const std::array<uint8_t, 32>& key,
                            uint32_t blockid,
                            const std::array<uint8_t, 12>& nonce,
                            const ustring& message) {
    
    ustring out;
    out.resize(message.size());
    
    int k = 0;
    for(int i = 0; i < (message.size()+63) /64; i++) {
        std::array<uint8_t, 64> ou = chacha20(key, nonce, i+blockid);
        for(int j = 0;  j < 64 and k < message.size(); j++, k++) {
            out[k] = ou[j];
        }
    }
    for(int i = 0; i < message.size(); i++) {
        out[i] ^= message[i];
    }
    return out;
}

void poly1305aes_test_clamp(uint8_t* r) {
     r[3] &= 15;
     r[7] &= 15;
     r[11] &= 15;
     r[15] &= 15;
     r[4] &= 252;
     r[8] &= 252;
     r[12] &= 252;
}

std::array<uint8_t, 16> poly1305_mac(const ustring message, const std::array<uint8_t, 32>& key) {
    constexpr uVar<192> prime130_5 ("0x3fffffffffffffffffffffffffffffffb");
    std::array<uint8_t, 24> r_bytes {0};
    std::copy_n(&key[0], 16, r_bytes.begin());
    poly1305aes_test_clamp(&r_bytes[0]);
    std::reverse(r_bytes.begin(), r_bytes.end());
    
    std::array<uint8_t, 24> s_bytes {0};
    std::copy_n(&key[16], 16, s_bytes.rbegin());

    uVar<192> accumulator ("0x0");
    uVar<192> r(r_bytes);
    uVar<192> s(s_bytes);


    for(int i = 0; i < ((message.size()+15)/16)*16; i+=16) {
        std::array<uint8_t,24> inp {0};
        assert(message.size() > i);
        
        auto siz = std::min(16ul, message.size() - i);
        
        std::copy_n(&message[i], siz, inp.begin());
        inp[siz] = 1;
        std::reverse(inp.begin(), inp.end());
        
        uVar<192> n(inp);

        accumulator += n;
        accumulator = (accumulator * r) % prime130_5;
        
    }
    
    
    accumulator += s;
    
    auto out = accumulator.serialise();
    std::array<uint8_t, 16> out_str;
    
    std::copy_n(out.rbegin(), 16, out_str.begin());
    
    return out_str;
}

std::array<uint8_t, 32> poly1305_key_gen(const std::array<uint8_t, 32>& key, const std::array<uint8_t, 12>& nonce) {
    std::array<uint8_t, 64> bl = chacha20(key, nonce, 0);
    std::array<uint8_t, 32> out;
    std::copy_n(bl.begin(), 32, out.begin());
    return out;
}




std::pair<ustring, std::array<uint8_t, 16>>
chacha20_aead_encrypt(ustring aad, std::array<uint8_t, 32> key, std::array<uint8_t, 8> iv,
                      std::array<uint8_t, 4> constant, ustring plaintext) {
    std::array<uint8_t, 12> nonce;
    std::copy(constant.begin(), constant.end(), nonce.begin());
    std::copy(iv.begin(), iv.end(), nonce.begin()+8);
    
    auto otk = poly1305_key_gen(key, nonce);
    
    auto ciphertext = chacha20_encrypt(key, 1, nonce, plaintext);
    
    for(unsigned c : ciphertext) {
        std::cout << c << " ";
    }
    std::cout << std::endl << std::endl;

    std::array<uint8_t, 4> aad_size;
    std::array<uint8_t, 4> cip_size;
    
    for(int i = 0; i < 4; i++) {
        aad_size[i] = (aad.size() >> (8*i)) & 0xff;
        cip_size[i] = (ciphertext.size() >> (8*i)) & 0xff;
    }
    //std::reverse(aad_size.begin(), aad_size.end());
    //std::reverse(cip_size.begin(), cip_size.end());
    
    aad.resize(((aad.size()+15)/16)*16, 0);
    ciphertext.resize(((ciphertext.size()+15)/16)*16, 0);
    
    ustring mac_data;
    mac_data.append(aad);
    mac_data.append(ciphertext);
    
    //tag = poly1305_mac(mac_data, otk)
    
    mac_data.append(aad_size.begin(), aad_size.end());
    mac_data.append(cip_size.begin(), cip_size.end());

    auto tag = poly1305_mac(mac_data, otk);
    return {ciphertext, tag};
}


void test() {
    std::array<uint8_t, 32> key = { 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86,
        0x87, 0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f, 0x90,
        0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97, 0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f };
    
    std::array<uint8_t, 12> nonce = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07 };
    
    
    auto oo = poly1305_key_gen(key, nonce);
    for( unsigned o : oo) {
        std::cout << std::hex<< o << " ";
    }
    
    std::string msg = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    
    ustring umsg;
    umsg.append(msg.begin(), msg.end());
    
    ustring aad = { 0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7 };
    
    std::array<uint8_t, 8> iv = { 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47};
    std::array<uint8_t, 4> con = { 0x07, 0x00, 0x00, 0x00 };
    
    auto [ciphertext, tag] =
    chacha20_aead_encrypt(aad, key, iv, con, umsg);
    
    for(unsigned c : ciphertext) {
        std::cout << c << " ";
    }
    std::cout << std::endl << std::endl;
    
    for(unsigned c : tag) {
        std::cout << c << " ";
    }
    std::cout << std::endl;
    
}
    
} // namespace fbw::cha
