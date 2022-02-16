//
//  pipe.hpp
//  https_server
//
//  Created by Frederick Benjamin Woodruff on 17/12/2021.
//

#ifndef pipe_hpp
#define pipe_hpp

#include <stdio.h>
#include <memory>

#include "global.hpp"


namespace fbw {

enum class status : unsigned {
    read_only, write_only, /*dormant,*/ closing, closed
    /*
     read_only means event loop should await data received from client
     read_write means poll if either available
     read_dormant means the server can read, but may also wake up and have something to send
     dormant means the server does not want to receive data but may awake and send something
     dead means kill the receiver
     */
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

#endif /* pipe_hpp */
