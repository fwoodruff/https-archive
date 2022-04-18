//
//  receiver.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 17/12/2021.
//

#ifndef receiver_hpp
#define receiver_hpp

#include <stdio.h>
#include <memory>

#include "global.hpp"


namespace fbw {

enum class status : unsigned {
    read_write, flush, closing, closed
};



struct status_message {
    ustring m_response;
    status m_status;
};

class receiver {
public:
    virtual status_message handle(ustring) noexcept =  0;
    virtual ~receiver() noexcept = default;
    std::unique_ptr<receiver> next = nullptr;
};




}

#endif /* receiver_hpp */
