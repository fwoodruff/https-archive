//
//  server.hpp
//  HTTPS Server
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
    using clist = std::list<connection>;
    static constexpr int max_listen = 10;
    poll_context m_poller;

    clist m_connections;
    std::vector<fpollfd> m_loop_events;
    tp m_loop_time;

    


    server_socket m_https_socket;
    server_socket m_redirect_socket;

    void accept_connection(const server_socket& sc, tp, std::function<std::unique_ptr<receiver>()> receiver_stack);
    void handle_event(fpollfd, tp) noexcept;
    

    
    
    
    

    


    
public:
    server();
    ~server(); // on windows startup/shutdown
    void serve_some();
    
};

} // namespace fbw



#endif /* server_hpp */

