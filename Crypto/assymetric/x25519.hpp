//
//  curve25519.hpp
//  curve25519
//
//  Created by Frederick Benjamin Woodruff on 08/08/2021.
//

#ifndef curve25519_hpp
#define curve25519_hpp

#include <array>

// get secret
namespace fbw::curve25519 {
[[nodiscard]] std::array<unsigned char,32>
    multiply(const std::array<unsigned char,32>& num,
                                  const std::array<unsigned char,32>& pnt) noexcept;
    // make key pair
[[nodiscard]] std::array<unsigned char,32>
    base_multiply(const std::array<unsigned char,32>& num) noexcept;

}

#endif /* curve25519_hpp */
