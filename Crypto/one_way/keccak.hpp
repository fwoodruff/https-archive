//
//  keccak.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 16/07/2021.
//
#ifndef keccak_hpp
#define keccak_hpp

#include "keccak.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>

namespace fbw {

class keccak_sponge {
    size_t capacity;
    size_t rate;
    std::array<uint8_t,200> state;
    size_t rate_in_bytes;
    size_t block_size;
    size_t idx;
    bool absorb_phase = true;
public:
    keccak_sponge(size_t capacity = 256) noexcept;
    // code duplication is better than undefined behaviour
    void absorb(const uint8_t* const input, size_t N) noexcept;
    void absorb(const char* const input, size_t N) noexcept;
    void squeeze(uint8_t* const output, size_t N) noexcept;
    void squeeze(char* const output, size_t N) noexcept;
    void reset() noexcept;
};

class cprng : keccak_sponge {
    bool init = false;
public:
    void randgen(uint8_t* const output, size_t N);
    [[nodiscard]] uint64_t randgen64();
};

extern thread_local cprng randomgen;

} // namespace fbw

#endif /* keccak_hpp */
