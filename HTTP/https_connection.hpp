//
//  http_connection.hpp
//  piformserver
//
//  Created by Frederick Benjamin Woodruff on 24/07/2021.
//

#ifndef https_connection_hpp
#define https_connection_hpp

#include "tls_protocol.hpp"

#include <string>

namespace fbw {

/*
 Handles HTTP streams
 */
class https_connection final : public tls_connection {
    static constexpr long max_bytes_queued = 1000000;
    
    std::string input;
    std::string header;
    void handle_session_data() final override;
    
public:
    static std::unique_ptr<connection_base> ctor_my();
};

} // namespace fbw

#endif /* http_connection_hpp */
