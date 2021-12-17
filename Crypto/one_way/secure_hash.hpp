
#ifndef secure_hash
#define secure_hash

#include <array>
#include <algorithm>
#include <vector>

#include "hash_base.hpp"
#include "global.hpp"

namespace fbw {

class sha256: public hash_base {
public:
    static constexpr int64_t block_size = 64;
    sha256();
    
    std::unique_ptr<hash_base> clone() const override;
    sha256& update(const uint8_t* begin, size_t size) override;
    [[nodiscard]] std::vector<uint8_t> hash() const & override;
    std::vector<uint8_t> hash() && override;
    [[nodiscard]] size_t get_block_size() const noexcept override;
private:
    size_t datalen;
    uint64_t bitlen;
    std::array<uint8_t,block_size> data;
    std::array<uint32_t,8> state;
    bool done;
    
};

class sha1 : public hash_base {
public:
    static constexpr int64_t block_size = 64;
    sha1();
    
    std::unique_ptr<hash_base> clone() const override;
    sha1& update(const uint8_t* begin, size_t size) override;
    std::vector<uint8_t> hash() const & override;
    std::vector<uint8_t> hash() && override;
    [[nodiscard]] size_t get_block_size() const noexcept override;

private:
    size_t datalen = 0;
    std::array<uint32_t,5> m_state;
    std::array<uint8_t,block_size> m_data;
    bool done;
    
};


class hmac {
    std::unique_ptr<const hash_base> m_factory;
    std::unique_ptr<hash_base> m_hasher;
    std::vector<uint8_t> KeyPrime;
public:
    hmac(std::unique_ptr<hash_base> hasher, const uint8_t* key, size_t size);
    hmac& update(const uint8_t* begin, size_t size);
    [[nodiscard]] ustring hash() const &;
    ustring hash() &&;

    hmac(const hmac &);
    hmac& operator=(const hmac &);
    ~hmac() noexcept = default;
};

} // namespace fbw

#endif   // secure_hash
