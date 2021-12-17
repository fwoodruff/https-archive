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




namespace fbw {


enum class connection_state : uint8_t { live, closing, closed };

using namespace std::chrono;

class poll_context;

/*
 Interface between TCP and TLS layers
 */
class connection_base {
private:
    std::vector<uint8_t> read_buffer;
    ssize_t read_buffer_end = 0;
    std::queue<ustring> write_buffer;
    size_t vec_start = 0;
    time_point<steady_clock> m_time_set;
    bool old_read_state;
    bool old_write_state;

    void read_some();
    void write_some();
    
    poll_context* context = nullptr;
    client_socket m_socket;
    
    friend class server;

    connection_state activity;
    
    bool read_buffer_empty() noexcept;
    bool read_buffer_full() noexcept;
    bool write_buffer_empty();

    

public:
    ssize_t bytes_queued_for_write;
    connection_base();
    virtual ~connection_base();
    connection_base(const connection_base& other) = delete;
    connection_base& operator=(const connection_base& other) = delete;
    
    void read_bytes(ustring&);
    ssize_t send_bytes(ustring bytes);
    void send_tcp_close_signal();
    void send_tcp_kill_signal();
    // void send_write_more();
    // need a map member
    
    virtual void handle_connection() noexcept = 0;
    std::unique_ptr<receiver> transport_later;
    
    /*
     std::shared_ptr<message_vertex> base;
     
     */
    
    
    
    
    
};

} // namespace fbw



#endif  /* connection_hpp */

