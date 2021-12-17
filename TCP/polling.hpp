//
//  poller.hpp
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

using node_ptr = std::list<std::unique_ptr<connection_base>>::iterator;


struct fpollfd {
    node_ptr node;
    bool read;
    bool write;
};


class poll_context {
#if __linux__
    fd_t m_epfd;
#else
    std::unordered_map<fd_t,fpollfd> m_events;
#endif
public:
    poll_context();
    ~poll_context();
    poll_context(const poll_context& other) = delete;
    poll_context& operator=(const poll_context& other) = delete;
    void add_fd(const cppsocket& sock, node_ptr return_object,
                bool read_state, bool write_state);
    void mod_fd(const cppsocket& sock, node_ptr return_object, bool read_state, bool write_state);
    void del_fd(const cppsocket& sock);

    std::vector<fpollfd> get_events(bool do_timeout);
};

} // namespace fbw


#endif /* polling_hpp */

