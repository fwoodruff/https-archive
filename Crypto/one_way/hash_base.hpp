//
//  hash_base.hpp
//  https_server
//
//  Created by Frederick Benjamin Woodruff on 17/12/2021.
//

#ifndef hash_base_hpp
#define hash_base_hpp

#include <stdio.h>
#include "global.hpp"
#include <memory>

namespace fbw {

class hash_base {
public:
    virtual ~hash_base() noexcept = default;
    virtual std::unique_ptr<hash_base> clone() const = 0;
    
    virtual hash_base& update(const uint8_t* begin, size_t size) = 0;
    virtual std::vector<uint8_t> hash() const & = 0;
    virtual std::vector<uint8_t> hash() && = 0;
    [[nodiscard]] virtual size_t get_block_size() const noexcept = 0;
};

}

#endif /* hash_base_hpp */
