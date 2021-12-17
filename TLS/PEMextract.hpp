//
//  PEMextract.hpp
//  basichttps
//
//  Created by Frederick Benjamin Woodruff on 04/12/2021.
//

#ifndef PEMextract_hpp
#define PEMextract_hpp

#include "global.hpp"

#include <stdio.h>
#include <array>
#include <string>
#include <vector>

namespace fbw {

std::array<unsigned char,32> privkey_from_file(std::string filename);

std::vector<ustring> der_cert_from_file(std::string filename);
} //namespace fbw


#endif /* PEMextract_hpp */
