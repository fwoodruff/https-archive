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
    std::array<unsigned char,32>
    multiply(const std::array<unsigned char,32>& num,
                                  const std::array<unsigned char,32>& pnt);
    // make key pair
    std::array<unsigned char,32>
    base_multiply(const std::array<unsigned char,32>& num);


    /*
    std::array<unsigned char, 64>
    ECDSA(const std::array<unsigned char,32>& ran,
          const std::array<unsigned char,32>& dig,
          const std::array<unsigned char,32>& priv);
     */
}

#endif /* curve25519_hpp */
