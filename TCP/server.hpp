//
//  server.hpp
//
//  Created by Frederick Benjamin Woodruff on 10/07/2021.
//



#ifndef server_hpp
#define server_hpp

#include "polling.hpp"
#include "connection.hpp"
#include "cppsocket.hpp"
#include "HTTP.hpp"


#include <memory>
#include <string>
#include <functional>
#include <list>


namespace fbw {

/*
 opens a TCP socket to the internet
 accepts new connections
 polls and handles data transfer on live connections
 removes stale connections
 */

using namespace std::chrono;
using tp = time_point<steady_clock,nanoseconds>;
server_socket get_listener_socket(std::string service);

class server {
    using clist = std::list<std::unique_ptr<connection>>;
    static constexpr int max_listen = 10;
    poll_context m_poller;
    clist connections;
    server_socket m_sock;

    void accept_connection(tp);
    void handle_event(fpollfd, tp) noexcept;
    
    std::string m_service;
    
    void sanity(const std::vector<fpollfd> events);

    
public:
    server(std::string service = "http");
    ~server(); // on windows startup/shutdown
    void serve_some();
    
};

} // namespace fbw



#endif /* server_hpp */

