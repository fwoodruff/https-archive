//
//  HTTP.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 24/07/2021.
//

#ifndef http_hpp
#define http_hpp

#include "receiver.hpp"

#include <string>

namespace fbw {

/*
 Handles HTTP streams
 */
class HTTP final : public receiver {
    static constexpr long max_bytes_queued = 1000000;
    
    std::string input;
    std::string header;

    std::string m_folder;
    bool m_redirect;
public:
    status_message handle(ustring) noexcept final override;
    HTTP(std::string folder, bool redirect);
    
};




} // namespace fbw
 
#endif /* http_hpp */
