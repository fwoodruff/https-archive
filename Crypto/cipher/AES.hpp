//
//  AES.hpp
//  AES_DIY
//
//  Created by Frederick Benjamin Woodruff on 03/09/2021.
//

#ifndef AES_hpp
#define AES_hpp

#include "global.hpp"

#include <stdio.h>
#include <array>


namespace fbw::aes {


/*
 AES encryption 
 */

using byte_word  = std::array<uint8_t,4>;
using aes_block = std::array<uint8_t, 16>;


template<int B>
struct roundkeys_t;

template<> struct roundkeys_t<128> { using round = std::array<byte_word, 44>; using key = std::array<uint8_t,16>; };
template<> struct roundkeys_t<192> { using round = std::array<byte_word, 52>; using key = std::array<uint8_t,24>; };
template<> struct roundkeys_t<256> { using round = std::array<byte_word, 60>; using key = std::array<uint8_t,32>; };

template<int B> using roundkey = typename roundkeys_t<B>::round;
template<int B> using aeskey = typename roundkeys_t<B>::key;


[[nodiscard]] roundkey<128> aes_key_schedule(const std::array<uint8_t,16>& AESkey) noexcept;
[[nodiscard]] roundkey<192> aes_key_schedule(const std::array<uint8_t,24>& AESkey) noexcept;
[[nodiscard]] roundkey<256> aes_key_schedule(const std::array<uint8_t,32>& AESkey) noexcept;

[[nodiscard]] aes_block aes_encrypt(aes_block plaintext, const roundkey<128>& roundkeys) noexcept;
[[nodiscard]] aes_block aes_encrypt(aes_block plaintext, const roundkey<192>& roundkeys) noexcept;
[[nodiscard]] aes_block aes_encrypt(aes_block plaintext, const roundkey<256>& roundkeys) noexcept;
[[nodiscard]] aes_block aes_decrypt(aes_block ciphertext, const roundkey<128>& roundkeys) noexcept;
[[nodiscard]] aes_block aes_decrypt(aes_block ciphertext, const roundkey<192>& roundkeys) noexcept;
[[nodiscard]] aes_block aes_decrypt(aes_block ciphertext, const roundkey<256>& roundkeys) noexcept;

} //fbw




#endif /* AES_hpp */
