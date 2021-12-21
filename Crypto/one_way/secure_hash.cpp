
#include "secure_hash.hpp"

#include "global.hpp"

#include <array>
#include <algorithm>
#include <iostream>
#include <cmath>
#include <iomanip>
#include <climits>
#include <cassert>
#include <vector>

namespace fbw {

uint32_t rotate_left(uint32_t a, uint32_t b) noexcept {
    //logger << "rotate_left()" << std::endl;
    file_assert(b < 32, "rotate_left");
    return (a << b) | (a >> (32-b));
}
uint32_t rotate_right(uint32_t a, uint32_t b) noexcept {
    //logger << "rotate_right()" << std::endl;
    
    file_assert(b < 32, "rotate_right");
    return (a >> b) | (a << (32-b));
}
uint32_t CH(uint32_t x, uint32_t y, uint32_t z) noexcept {
    //logger << "CH()" << std::endl;
    return (x & y) ^ (~x & z);
}
uint32_t MAJ(uint32_t x, uint32_t y, uint32_t z) noexcept {
    //logger << "MAJ()" << std::endl;
    return (x & y) ^ (x & z) ^ (y & z);
}
uint32_t EP0(uint32_t x) noexcept {
    //logger << "EP0()" << std::endl;
    return rotate_right(x,2) ^ rotate_right(x,13) ^ rotate_right(x,22);
}
uint32_t EP1(uint32_t x) noexcept {
    //logger << "EP1()" << std::endl;
    return rotate_right(x,6) ^ rotate_right(x,11) ^ rotate_right(x,25);
}
uint32_t SIG0(uint32_t x) noexcept {
    //logger << "SIG0()" << std::endl;
    return rotate_right(x,7) ^ rotate_right(x,18) ^ ((x) >> 3);
}
uint32_t SIG1(uint32_t x) noexcept {
    //logger << "SIG1()" << std::endl;
    return rotate_right(x,17) ^ rotate_right(x,19) ^ ((x) >> 10);
}

constexpr double sq_root(double x) noexcept {
    assert(x >= 0 );
    constexpr double small = 9*std::numeric_limits<double>::epsilon();
    double guess = 1;
    double diff = 1;
    while(diff > small or diff < -small) {
        double root = 0.5*(guess + x/guess);
        diff = guess - root;
        guess = root;
    }
    return guess;
}

constexpr double cube_root(double x) noexcept {
    assert(x >= 0);
    constexpr double small = 9*std::numeric_limits<double>::epsilon();
    double guess = 1;
    double diff = 1;
    while(diff > small or diff < -small) {
        double root = ((2*guess + x/(guess*guess))/3);
        diff = guess - root;
        guess = root;
    }
    return guess;
}

void sha256_transform(std::array<uint32_t,8>& state, const std::array<uint8_t,64> data) noexcept {
    //logger << "sha256_transform()" << std::endl;
    static constexpr std::array<uint32_t,64> k = [](){
        int idx = 0;
        std::array<uint32_t,64> kl {};
        for (int i = 2; i <= 311; i++) {
            bool flag = true;
            for (int j = 2; j <= i / 2; ++j) {
                if (i % j == 0) {
                    flag = false;
                    break;
                }
            }
            if (flag) {
                auto x = cube_root(i);
                kl[idx++] = unsigned((x - unsigned(x))*(1ULL<<32 ));
            }
        }
        return kl;
    }();
    std::array<uint32_t,64> m;
    for (int i = 0, j = 0; i < 16; ++i, j += 4) {
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    }
    for (int i = 16 ; i < 64; ++i) {
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];
    }

    auto vars = state;
    for (int i = 0; i < 64; ++i) {
        uint32_t t1 = vars[7] + EP1(vars[4]) + CH(vars[4],vars[5],vars[6]) + k[i] + m[i];
        uint32_t t2 = EP0(vars[0]) + MAJ(vars[0],vars[1],vars[2]);
        for(int i = 7; i >0; i--) {
            vars[i] = vars[i-1];
        }
        vars[4] += t1;
        vars[0] = t1 + t2;
    }
    for(int i = 0; i < 8; i ++) {
        state[i] += vars[i];
    }
}

size_t sha256::get_block_size() const noexcept {
    //logger << "sha256::get_block_size()" << std::endl;
    return block_size;
}

std::unique_ptr<::fbw::hash_base> sha256::clone() const {
    //logger << "sha256::clone()" << std::endl;
    return std::make_unique<sha256>(*this);
}


sha256::sha256() noexcept  : datalen(0),  bitlen(0), data(), done(false) {
    //logger << "sha256::sha256()" << std::endl;
    constexpr auto state0 = [](){
        int idx = 0;
        std::array<uint32_t,8> kl {};
        for (int i = 2; i <= 19; i++) {
            bool flag = true;
            for (int j = 2; j <= i / 2; ++j) {
                if (i % j == 0) {
                    flag = false;
                    break;
                }
            }
            if (flag) {
                auto x = sq_root(i);
                kl[idx++] = unsigned((x - unsigned(x))*(1ULL<<32 ));
            }
        }
        return kl;

    }();
    state = state0;
}


sha256& sha256::update(const uint8_t* const begin, size_t size) noexcept {
    //logger << "sha256::update()" << std::endl;
    for (size_t i = 0; i < size; ++i) {
        file_assert(datalen < data.size());
        data[datalen++] = begin[i];
        if (datalen == 64) {
            sha256_transform(state, data);
            bitlen += 512;
            datalen = 0;
        }
    }
    return *this;
}

sha256& sha256::update(const ustring& input) noexcept {
    //logger << "sha256::update()" << std::endl;
    for (size_t i = 0; i < input.size(); ++i) {
        file_assert(datalen < data.size());
        data[datalen++] = input[i];
        if (datalen == 64) {
            sha256_transform(state, data);
            bitlen += 512;
            datalen = 0;
        }
    }
    return *this;
}

std::vector<uint8_t> sha256::hash() &&  noexcept {
    //logger << "sha256::hash() && " << std::endl;
    //assert(!done);
    file_assert(!done, "sha256::hash() done");
    std::vector<uint8_t> hash;
    hash.resize(32);
    size_t dlen = datalen;
    data[dlen++] = 0x80;
    while (dlen < 56) {
        data[dlen++] = 0x00;
    }
    if (datalen >= 56) {
        sha256_transform(state, data);
        std::fill_n(data.begin(),56,0);
    }
    bitlen += datalen * sizeof(bitlen);
    for(size_t i = 0; i < sizeof(bitlen); i++) {
        data[63-i] = bitlen >> (CHAR_BIT * i);
    }
    sha256_transform(state, data);
    for (size_t i = 0; i < sizeof(state[0]); ++i) {
        for(size_t j = 0; j < CHAR_BIT; j++) {
            hash[i + j*sizeof(state[0])]= (state[j] >> (24 - i * CHAR_BIT)) & 0xff;
        }
    }
    done = true;
    return hash;
}


std::vector<uint8_t> sha256::hash() const & {
    //logger << "sha256::hash() const &" << std::endl;
    sha256 other = *this;
    return std::move(other).hash();
}




sha1::sha1() : datalen(0), m_data({}), done(false) {
    //logger << "sha1::sha1()" << std::endl;
    m_state[0] = 0x67452301;
    m_state[1] = 0xEFCDAB89;
    m_state[2] = 0x98BADCFE;
    m_state[3] = 0x10325476;
    m_state[4] = 0xC3D2E1F0;
}

uint32_t asval_unsafe32(const uint8_t * const s) {
    //logger << "asval_unsafe32()" << std::endl;
    uint32_t len = 0;
    for(size_t i = 0; i < 4; i++) {
        len <<=8;
        len |= static_cast<uint8_t>(s[i]);
    }
    return len;
}

void sha1_transform(std::array<uint32_t,5>& state, std::array<uint8_t,64>& data) {
    //logger << "sha1_transform()" << std::endl;
    std::array<uint32_t,80> w;
    for(int i = 0; i < 16; i++) {
        w[i] = asval_unsafe32(&data[i*4]);
    }
    for (int i = 16; i < 80; i++) {
        w[i] = rotate_left((w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16]), 1);
    }

    auto a = state[0];
    auto b = state[1];
    auto c = state[2];
    auto d = state[3];
    auto e = state[4];
    for (int i = 0 ; i < 80; i ++) {
        uint32_t f, k;
        switch(i/20) {
            case 0:
                f = (b & c) | ((~ b) & d);
                k = 0x5A827999;
                break;
            case 1:
                f = b ^ c ^ d;
                k = 0x6ED9EBA1;
                break;
            case 2:
                f = (b & c) | (b & d) | (c & d);
                k = 0x8F1BBCDC;
                break;
            case 3:
                f = b ^ c ^ d;
                k = 0xCA62C1D6;
                break;
            default:
                assert (false);
        }
        auto temp = rotate_left(a, 5) + f + e + k + w[i];
        e = d;
        d = c;
        c = rotate_left(b, 30);
        b = a;
        a = temp;
    }
    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    data = {0};
}

sha1& sha1::update(const uint8_t* const begin, size_t size) noexcept {
    //logger << "sha1::update()" << std::endl;
    for(size_t i = 0; i < size; i++) {
        m_data[datalen % block_size] = begin[i];
        datalen++;
        if(datalen % block_size == 0) {
            sha1_transform(m_state, m_data);
        }
    }
    
    return *this;
}

sha1& sha1::update(const ustring& input) noexcept {
    //logger << "sha1::update()" << std::endl;
    for(size_t i = 0; i < input.size(); i++) {
        m_data[datalen % block_size] = input[i];
        datalen++;
        if(datalen % block_size == 0) {
            sha1_transform(m_state, m_data);
        }
    }
    return *this;
}

std::vector<uint8_t> sha1::hash() && noexcept {
    //logger << "sha1::hash() &&" << std::endl;
    file_assert(!done, "sha1::hash() done");
    m_data[datalen%block_size] = 0x80;
    
    if(datalen%block_size >= 56) {
        sha1_transform(m_state,m_data);
    }
    write_int(datalen * 8, &m_data[56], 8);
    sha1_transform(m_state,m_data);
    std::vector<uint8_t> hash;
    hash.resize(20);
    for(int i = 0; i < 5; i ++) {
        write_int(m_state[i], &hash[i*4], 4);
    }
    
    return hash;
}

std::vector<uint8_t> sha1::hash() const & {
    //logger << "sha1::hash() const &" << std::endl;
    sha1 other = *this;
    return std::move(other).hash();
}

size_t sha1::get_block_size() const noexcept {
    //logger << "sha1::get_block_size()" << std::endl;
    return block_size;
}

std::unique_ptr<hash_base> sha1::clone() const {
    //logger << "sha1::clone()" << std::endl;
    return std::make_unique<sha1>(*this);
}

hmac::hmac(std::unique_ptr<hash_base> hasher, const uint8_t* key, size_t keylen) {
    //logger << "hmac::hmac()" << std::endl;
    m_factory = std::move(hasher);
    m_hasher = m_factory->clone();
    KeyPrime.resize(m_factory->get_block_size());
    if(keylen > m_factory->get_block_size()) {
        auto hsh = m_factory->clone()->update(key, keylen).hash();
        std::copy(hsh.begin(), hsh.end(), KeyPrime.begin());
    } else {
        std::copy_n(key, keylen, KeyPrime.begin());
    }
    assert(KeyPrime.size() == 64);
    ustring ipadkey;
    ipadkey.resize(m_factory->get_block_size());
    assert(ipadkey.size() == 64);
    std::transform(KeyPrime.begin(), KeyPrime.end(), ipadkey.begin(), [](uint8_t c){return c ^ 0x36;});
    m_hasher->update(ipadkey);
}


hmac& hmac::update(const ustring& data) {
    //logger << "hmac::update()" << std::endl;
    m_hasher->update(data);
    return *this;
}

hmac& hmac::update(const uint8_t* data, size_t datalen) {
    //logger << "hmac::update()" << std::endl;
    m_hasher->update(data,datalen);
    return *this;
}

ustring hmac::hash() && {
    //logger << "hmac::hash()" << std::endl;
    std::vector<uint8_t> opadkey;
    opadkey.resize(m_factory->get_block_size());
    file_assert(opadkey.size() == 64);
    std::transform(KeyPrime.begin(), KeyPrime.end(), opadkey.begin(), [](uint8_t c){return c ^ 0x5c;});
    auto hsh = m_hasher->hash();
    file_assert(!hsh.empty(), "empty hash");
    
    auto outsha = m_factory->clone();
    outsha->update(&opadkey[0], opadkey.size());
    outsha->update(&hsh[0], hsh.size());
    auto outarr = outsha->hash();
    ustring outvec;
    outvec.append(outarr.begin(), outarr.end());
    return outvec;
}

ustring hmac::hash() const & {
    hmac other (*this);
    return std::move(other).hash();
}

hmac::hmac(const hmac& other) {
    *this = other;
}

hmac& hmac::operator=(const hmac & other) {
    if (this == &other) return *this;
    m_factory = other.m_factory->clone();
    m_hasher = other.m_hasher->clone();
    KeyPrime = other.KeyPrime;
    return *this;
}





} // namespace fbw


