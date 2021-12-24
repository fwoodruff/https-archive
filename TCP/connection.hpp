//
//  connect.hpp
//  piserver
//
//  Created by Frederick Benjamin Woodruff on 09/07/2021.
//




#ifndef connection_hpp
#define connection_hpp

#include "cppsocket.hpp"
#include "connection.hpp"
#include "global.hpp"
#include "receiver.hpp"
#include "polling.hpp"


#include <unistd.h>
#include <poll.h>

#include <cstdlib>
#include <ctime>
#include <cassert>
#include <string>
#include <array>
#include <unordered_map>
#include <queue>
#include <chrono>
#include <list>
#include <memory>




namespace fbw {



using namespace std::chrono;

class poll_context;

/*
 Interface between TCP and TLS layers
 */
class connection {
private:
    ustring write_buffer;
    size_t vec_start = 0;
    time_point<steady_clock> m_time_set;

    poll_context* context = nullptr;
    client_socket m_socket;
    
    friend class server;

    status activity;
    
    ustring receive_bytes_from_network();
    ssize_t queue_bytes_for_write(ustring bytes);
    void send_bytes_over_network();

public:

    connection();
    
    void push_receiver(std::unique_ptr<receiver> r);
    
    ~connection();
    connection(const connection& other) = delete;
    connection& operator=(const connection& other) = delete;

    // returns true if the connection finished
    bool handle_connection(fpollfd, time_point<steady_clock,nanoseconds>) noexcept;
    std::unique_ptr<receiver> primary_receiver;

};

} // namespace fbw



#endif  /* connection_hpp */

