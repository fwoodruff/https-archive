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

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> parent of 505c7de (TCP)
//#include <mutex>
//#include <thread>
//#include <condition_variable>
//#include <atomic>
=======
#include <mutex>
#include <thread>
#include <condition_variable>
#include <atomic>
>>>>>>> parent of a8b46b4 (reverting)
        


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
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
    clist m_connections;
    std::vector<fpollfd> m_loop_events;
    tp m_loop_time;
=======
    clist connections;
>>>>>>> parent of 02818c2 (threadpooled the connection handling event loop)
=======
    clist connections;
    std::vector<fpollfd> loop_events;
    tp loop_time;
>>>>>>> parent of a8b46b4 (reverting)
=======
    clist m_connections;
    std::vector<fpollfd> m_loop_events;
    tp m_loop_time;
>>>>>>> parent of 505c7de (TCP)
    server_socket m_https_socket;
    server_socket m_redirect_socket;

    void accept_connection(const server_socket& sc, tp, std::function<std::unique_ptr<receiver>()> receiver_stack);
    void handle_event(fpollfd, tp) noexcept;
    
    
    void server_thread_task();
    void do_task(fpollfd event);
    bool get_task();
    std::vector<std::thread> thread_vec;
    std::mutex mut;
    std::condition_variable pool_cv;
    std::condition_variable loop_cv;
    bool done = false;
    size_t threads_to_start = 0;

    int events_started = 0;
    size_t threads_finished = 0;

    
public:
    server();
    ~server(); // on windows startup/shutdown
    void serve_some();
    
};

} // namespace fbw



#endif /* server_hpp */

