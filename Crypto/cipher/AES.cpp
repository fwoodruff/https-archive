//
//  AES.cpp
//  AES_DIY
//
//  Created by Frederick Benjamin Woodruff on 03/09/2021.
//
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf

#include "AES.hpp"
#include "global.hpp"

#include <stdint.h>
#include <algorithm>
#include <iostream>
#include <iomanip>

/*
 This performs AES encryption and decryption on 16 byte blocks of data, using 128 bit, 192 bit and 256 bit keys
 */

namespace fbw::aes {


constexpr int Nb = 4;
template<int BITS> constexpr int Nk = BITS/32;
template<int BITS> constexpr int Nr = Nk<BITS> + 6;


void AddRoundKey(aes_block& b, const byte_word* const roundkey) noexcept;
void InvMixColumns(aes_block&) noexcept;
void InvShiftRows(aes_block&) noexcept;
void InvSubBytes(aes_block&) noexcept;
void MixColumns(aes_block&) noexcept;
void ShiftRows(aes_block&) noexcept;
void SubBytes(aes_block&) noexcept;

template<int BITS> [[nodiscard]] roundkey<BITS> KeyExpansion(const aeskey<BITS>& AESkey) noexcept;
template<int BITS> [[nodiscard]] aes_block cipher(aes_block plaintext, const roundkey<BITS>&) noexcept;
template<int BITS> [[nodiscard]] aes_block InvCipher(aes_block ciphertext, const roundkey<BITS>& roundkeys) noexcept;

// rotates the bits of a byte e.g.  10001001 -> 00010011
constexpr uint8_t ROTL8(uint8_t x, int shift) {
    return (x << shift) | (x >> (8 - shift));
}

/*
 AES has a reversible substitution step
 */
constexpr std::array<uint8_t,256> SBOX = [](){
    // https://en.wikipedia.org/wiki/Rijndael_S-box
    std::array<uint8_t,256> sbox {0};
    uint8_t p = 1, q = 1;
    do {
        /* multiply p by 3 */
        p = p ^ (p << 1) ^ (p & 0x80 ? 0x1B : 0);
        /* divide q by 3 (equals multiplication by 0xf6) */
        q ^= q << 1;
        q ^= q << 2;
        q ^= q << 4;
        q ^= q & 0x80 ? 0x09 : 0;
         
        /* compute the affine transformation */
        uint8_t xformed = q ^ ROTL8(q, 1) ^ ROTL8(q, 2) ^ ROTL8(q, 3) ^ ROTL8(q, 4);
        sbox[p] = xformed ^ 0x63;
    } while (p != 1);

    /* 0 is a special case since it has no inverse */
    sbox[0] = 0x63;
    return sbox;
}();

/*
 This inverts the array computed above
 */
constexpr std::array<uint8_t,256> INVSBOX = [](){
    std::array<uint8_t,256> invsbox {0};
    for(int i = 0; i < 256; i++) {
        invsbox[SBOX[i]] = i;
    }
    return invsbox;
}();



/*
 performs the SBOX substitution
 */
void SubBytes(aes_block& state) noexcept {
    for(auto& val : state) {
        val = SBOX[val];
    }
}

/*
 reverses the SBOX substitution
 */
void InvSubBytes(aes_block& state) noexcept {
    for(auto& val : state) {
        val = INVSBOX[val];
    }
}

/*
 performs the row rotation
 */
void ShiftRows(aes_block& b) noexcept {
    std::array<uint8_t,Nb> temp;
    for(int i = 1; i < 4; i++) {
        for(int j = 0; j < Nb; j++) {
            temp[j] = b[(4*(i+j)+i)%(4*Nb)];
        }
        for(int j = 0; j < 4; j++) {
            b[i + 4*j] = temp[j];
        }
    }
}

/*
 inverts the row rotation
 */
void InvShiftRows(aes_block& b) noexcept {
    std::array<uint8_t,Nb> temp;
    for(int i = 1; i < 4; i++) {
        for(int j = 0; j < Nb; j++) {
            temp[j] = b[(4*((Nb-i)+j)+i)%(4*Nb)];
        }
        for(int j = 0; j < 4; j++) {
            b[i + 4*j] = temp[j];
        }
    }
}

/*
 performs all Galois field multiplications at runtime
 */
constexpr uint8_t GMul_explicit(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    for (int i = 0; i < 8; i++) {
        if ((b & 1) != 0) {
            p ^= a;
        }
        bool hi_bit_set = (a & 0x80) != 0;
        a <<= 1;
        if (hi_bit_set) {
            a ^= 0x1B; /* x^8 + x^4 + x^3 + x + 1 */
        }
        b >>= 1;
    }
    return p;
}

/*
 Caches the Galois field multiplications and retrieves from the cache
 */
uint8_t GMul(uint8_t a, uint8_t b) {
    assert(a < 16);
    constexpr auto res = [](){
        std::array<std::array<uint8_t,256>,16> resa {{}};
        for(int i = 0; i < 16; i++) {
            for(int j = 0; j < 256; j++) {
                resa[i][j] = GMul_explicit(i,j);
            }
        }
        return resa;
    }();
    return res[a][b];
}


/*
 Used in the mix columns function
 */
void mult_columns(aes_block& b, std::array<uint8_t,4> a) {
    for (int c = 0; c < Nb; c++) {
        std::array<uint8_t,4> col {0};
        for(int j = 0; j < 4; j++) {
            for(int k = 0; k < 4; k++) {
                col[j] ^= GMul(a[(3-j+k)%4], b[c*4 + k]);
            }
        }
        for(int j = 0; j < 4; j++) {
            b[c*Nb + j] = col[j];
        }
    }
}

/*
 Mix columns is the Galois field multiplication of each column in an AES block
 */
void MixColumns(aes_block& b) noexcept {
    mult_columns(b, {3,1,1,2});
}

/*
 reverses the Mix column function.
 */
void InvMixColumns(aes_block& b) noexcept {
    mult_columns(b, {11,13,9,14});
}

/*
 xor a round key with the block
 */
void AddRoundKey(aes_block& b, const byte_word* const roundkey) noexcept {
    for(int i = 0; i < Nb; i++) {
        for(int j = 0; j < 4; j++) {
            b[i + j*Nb] ^= roundkey[j][i];
        }
    }
}

/*
 Round constants used in the key expansion
 */
constexpr auto Rcon = [](){
    std::array<uint8_t,32> res {0};
    uint8_t c = 1;
    for(int i = 1; i < 32; i ++) {
        res[i] = c;
        c = GMul_explicit(2, c);
    }
    return res;
}();

/*
 Template for expanding out the input secret encryption/decryption key
 Below are instantiations for 128 bit, 192 bit, and 256 bit keys
 */
template<int BITS>
roundkey<BITS> KeyExpansion(const aeskey<BITS>& AESkey) noexcept {
    roundkey<BITS> keybytes;
    for(int i = 0; i < Nk<BITS>; i++) {
        for(int j = 0; j < 4; j++) {
            keybytes[i][j] = AESkey[4*i +j];
        }
    }
    for(int i = Nk<BITS>; i < Nb * (Nr<BITS>+1); i++) {
        byte_word temp;
        temp = keybytes[i-1];
        
        if (i % Nk<BITS> == 0) {
            std::rotate(temp.begin(),&temp[1],temp.end());
            std::transform(temp.begin(), temp.end(), temp.begin(), [](uint8_t c) { return SBOX[c]; });
            temp[0] ^= Rcon[i/Nk<BITS>];
        } else if (Nk<BITS> > 6 and i % Nk<BITS> == 4) {
            std::transform(temp.begin(), temp.end(), temp.begin(), [](uint8_t c) { return SBOX[c]; });
        }
        const auto& kb = keybytes[i-Nk<BITS>];
        std::transform(kb.begin(), kb.end(), temp.begin(), keybytes[i].begin(), std::bit_xor<uint8_t>());
    }
    return keybytes;
}
roundkey<128> aes_key_schedule(const aeskey<128>& AESkey) noexcept {
    return KeyExpansion<128>(AESkey);
}
roundkey<192> aes_key_schedule(const std::array<uint8_t,24>& AESkey) noexcept {
    return KeyExpansion<192>(AESkey);
}
roundkey<256> aes_key_schedule(const std::array<uint8_t,32>& AESkey) noexcept {
    return KeyExpansion<256>(AESkey);
}

/*
 performs the encryption on a block
 */
template<int BITS>
aes_block cipher(aes_block state, const roundkey<BITS>& w) noexcept {
    AddRoundKey(state, &w[0]);
    for (int i = 1; i < Nr<BITS>; i++) {
        SubBytes(state);
        ShiftRows(state);
        MixColumns(state);
        AddRoundKey(state, &w[Nb*i]);
    }
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, &w[Nb*Nr<BITS>]);
    return state;
}
aes_block aes_encrypt(aes_block plaintext, const roundkey<128>& roundkeys) noexcept {
    return cipher<128>(plaintext, roundkeys);
}
aes_block aes_encrypt(aes_block plaintext, const roundkey<192>& roundkeys) noexcept {
    return cipher<192>(plaintext, roundkeys);
}
aes_block aes_encrypt(aes_block plaintext, const roundkey<256>& roundkeys) noexcept {
    return cipher<256>(plaintext, roundkeys);
}

/*
 template for performing the decryption on a block
 instantiations below
 */
template<int BITS>
aes_block InvCipher(aes_block state, const roundkey<BITS>& w) noexcept {
    AddRoundKey(state, &w[Nb*Nr<BITS>]);
    for (int i = Nr<BITS>-1; i >= 1; i--) {
        InvShiftRows(state);
        InvSubBytes(state);
        AddRoundKey(state, &w[Nb*i]);
        InvMixColumns(state);
    }
    InvShiftRows(state);
    InvSubBytes(state);
    AddRoundKey(state, &w[0]);
    return state;
}
aes_block aes_decrypt(aes_block ciphertext, const roundkey<128>& roundkeys) noexcept {
    return InvCipher<128>(ciphertext, roundkeys);
}
aes_block aes_decrypt(aes_block ciphertext, const roundkey<192>& roundkeys) noexcept {
    return InvCipher<192>(ciphertext, roundkeys);
}
aes_block aes_decrypt(aes_block ciphertext, const roundkey<256>& roundkeys) noexcept {
    return InvCipher<256>(ciphertext, roundkeys);
}

} // namespace fbw::aes
