//
//  http_connection.hpp
//  piformserver
//
//  Created by Frederick Benjamin Woodruff on 24/07/2021.
//

#ifndef https_connection_hpp
#define https_connection_hpp

#include "receiver.hpp"

#include <string>

namespace fbw {

/*
 Handles HTTP streams
 */

// rename to just http
class HTTP final : public receiver {
    static constexpr long max_bytes_queued = 1000000;
    
    std::string input;
    std::string header;

public:
    status_message handle(ustring) noexcept final override;

};

} // namespace fbw

#endif /* http_connection_hpp */
