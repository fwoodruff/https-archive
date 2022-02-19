//
//  polling.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 10/07/2021.
//

#ifndef polling_hpp
#define polling_hpp


#include "connection.hpp"
#include "cppsocket.hpp"


#include <poll.h>

#include <cstdio>
#include <vector>
#include <array>
#include <unordered_map>
#include <list>



namespace fbw {

class connection;





class poll_context {
#if __linux__
    fd_t m_epfd;
    std::unordered_map<fd_t,event_var> m_events;
#else
    std::unordered_map<fd_t,fpollfd> m_events;
#endif
public:
    poll_context();
    ~poll_context();
    poll_context(const poll_context& other) = delete;
    poll_context& operator=(const poll_context& other) = delete;
    void add_fd(const cppsocket& sock, event_var return_object,
                bool read_state, bool write_state);
    void mod_fd(const cppsocket& sock, bool read_state, bool write_state);
    void del_fd(const cppsocket& sock);

    std::vector<fpollfd> get_events(bool do_timeout);
};

} // namespace fbw


#endif /* polling_hpp */

