//
//  server.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 12/07/2021.
//


#include "connection.hpp"
#include "cppsocket.hpp"
#include "server.hpp"
#include "global.hpp"
#include "HTTP.hpp"
#include "TLS.hpp"

#include <fcntl.h> // for F_SETFL, O_NONBLOCK
#include <poll.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <netinet/in.h>


#include <ctime>
#include <cstdlib>
#include <string>
#include <array>
#include <exception>
#include <unordered_map>
#include <iostream>
#include <memory>
#include <algorithm>
#include <cerrno>
#include <cassert>
#include <cstring>
#include <fstream>
#include <chrono>
#include <sstream>

#include <variant>


using namespace std::chrono;

namespace fbw {

/*
 Will be used for extracting IP information from sockets
 */
in_port_t get_in_port(struct sockaddr *sa) {
    // sockaddr and sockaddr_in6 are differently aligned?
    if (sa->sa_family == AF_INET) {
        return reinterpret_cast<struct sockaddr_in*>(sa)->sin_port;
    }
    return reinterpret_cast<struct sockaddr_in6*>(sa)->sin6_port;
}

/*
 Opens a server socket
 */
server_socket get_listener_socket(std::string service) {
    server_socket listener;
    struct addrinfo hints, *ai, *p;

    memset(&hints,0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    
   
    // The DF flag is set for the IP packet by most operating systems for the HTTPS 443 port.
    if(::getaddrinfo(nullptr, service.c_str(), &hints, &ai) != 0) {
        throw std::system_error(errno, std::generic_category());
    }

    for(p = ai; p != nullptr; p = p->ai_next) {
        try {

            listener = server_socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            
            int yes;
            listener.setsockopt(SOL_SOCKET, SO_REUSEADDR, &(yes=1), sizeof(int));
            listener.bind(p->ai_addr, p->ai_addrlen);
        } catch (const std::system_error& e ) {
            continue;
        }
        break;
    }
    freeaddrinfo(ai);
    if(p == nullptr) {
        throw std::runtime_error("Could not bind socket");
    }
    listener.listen(10);
    listener.fcntl(F_SETFL, O_NONBLOCK);
    return listener;
}
/*
 constructs a server.
 The ctor argument is the data stream handler
 The service is used to infer the correct port number
 */
server::server() {
    m_https_socket = get_listener_socket("https");
    m_redirect_socket = get_listener_socket("http");
    
    m_poller.add_fd(m_https_socket, static_fd::https_acceptor, true, false);
    m_poller.add_fd(m_redirect_socket, static_fd::http_acceptor, true, false);
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> parent of 505c7de (TCP)
=======
>>>>>>> parent of ebdb5c6 (reverse)
    can_accept_old = true;

    //unsigned nthreads = std::thread::hardware_concurrency();
    //nthreads = std::clamp(nthreads, 1u, static_cast<unsigned int> (MAX_SOCKETS));
    //for(unsigned i = 0; i < nthreads - 1; i++) {
        //m_threads.emplace_back(&server::server_thread_task, this);
    //}
    
=======
>>>>>>> parent of a8b46b4 (reverting)
    

    unsigned nthreads = std::thread::hardware_concurrency();
    nthreads = std::clamp(nthreads, 1u, static_cast<unsigned int> (MAX_SOCKETS));
    for(unsigned i = 0; i < nthreads - 1; i++) {
        thread_vec.emplace_back(&server::server_thread_task, this);
    }
    
=======

>>>>>>> parent of 02818c2 (threadpooled the connection handling event loop)

    // interthread/intersocket, need a way for server to initiate message.
    // server-wide pipe
    // write_more and await_pipe maps, to 'add' those events to active.
    // connection should be a shared_ptr and maps should be weak pointers.
    // if write_more not empty, don't block on poll.
    // wakeups could be spurious.
}

/*
 This is the main program loop, accepting and handling connections.
 
 The central data structure is an epoll context which returns pointers (iterators) to doubly linked list nodes.
 Polled nodes, splice themselves onto the front of the list.
 Stale nodes are therefore found at the back of the list and can be reclaimed
 
 The goal is to keep overheads as low as possible when handling a large number of low-load connections.
 We want to keep active connections open to minimise the number of expensive handshakes we need to negotiate.
 This design is overkill until I implement some kind of parallelism (proxy servers or GPU handshake/cipher acceleration)
 
 To do:
 Implement resumption of old TLS sessions on new connections.
 This will involve an LRU cache of session keys, but where no IP is allowed multiple entries
 */




template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

<<<<<<< HEAD
void server::do_task(fpollfd event) {
    std::visit(overloaded {
        [&](node_ptr arg) {
            file_assert(arg != connections.end(), "fd = end");
            arg->handle_connection(event, loop_time);
            
            logger << "event type: connection\n";
            
            if(arg->activity ==  status::closed) {
                std::lock_guard lk(mut);
                connections.erase(arg);
            } else {
                bool poll_for_read  = (arg->activity ==  status::read_write);
                bool poll_for_write = arg->activity != status::closed and (!arg->write_buffer.empty() or
                                      (arg->activity == status::flush));
                if(arg->old_read != poll_for_read or arg->old_write != poll_for_write)
                {
                    std::lock_guard lk(mut);
                    m_poller.mod_fd(arg->m_socket, poll_for_read, poll_for_write);
                }
                arg->old_read = poll_for_read;
                arg->old_write = poll_for_write;
            }
        },
        [&](static_fd arg) {
            try {
                logger << "event type: acceptor\n";
                switch (arg) {
                    case static_fd::https_acceptor:
                        accept_connection(m_https_socket,
                                          loop_time,
                                        [] {
                            auto x = std::make_unique<fbw::TLS>();
                            x->next = std::make_unique<fbw::HTTP>(fbw::rootdir, false);
                            return x;
                        });
                        break;
                    case static_fd::http_acceptor:
                        accept_connection(m_redirect_socket,
                                          loop_time,
                                    [] {
                            return std::make_unique<fbw::HTTP>(fbw::rootdir, true);
                        });
                        break;
                    default:
                        break;
                }
            } catch(const std::runtime_error& e) {
                logger << e.what() << std::endl;
            }
        }
    }, event.node);
}

bool server::get_task() {
    unsigned idx;
    {
        std::lock_guard lk(mut);
        idx = events_started;
        if(idx == loop_events.size()) {
            threads_finished++;
            return false;
        } else {
            events_started++;
        }
    }
    do_task(loop_events[idx]);
    return true;
}

void server::server_thread_task() {
    while(true) {
        {
            std::unique_lock<std::mutex> lk(mut);
            pool_cv.wait(lk, [&]{ return threads_to_start != 0 or done;});
            if(done) {
                break;
            }
            threads_to_start--;
        }
        pool_cv.notify_one();
        while(get_task()) { }
        loop_cv.notify_one();
        
    }
    pool_cv.notify_one();
}
=======
>>>>>>> parent of 02818c2 (threadpooled the connection handling event loop)


static int loop_index = 0;

void server::serve_some() {
<<<<<<< HEAD
    loop_index++;
    logger << "loop count: " << loop_index << std::endl;
    
    bool can_accept = connections.size() < static_cast<size_t>(MAX_SOCKETS - 11);
    m_poller.mod_fd(m_https_socket, can_accept, false);
    m_poller.mod_fd(m_redirect_socket, can_accept, false);
    loop_time = steady_clock::now();
    logger << "num connections: " << connections.size() << std::endl;
    loop_events = m_poller.get_events(!connections.empty());
    logger << "num connections polled: " << loop_events.size() << std::endl;
    
    events_started = 0;
    threads_finished = 0;
    

    {
        std::lock_guard<std::mutex> lk(mut);
        threads_to_start = thread_vec.size();
    }
<<<<<<< HEAD
    //m_pool_cv.notify_one();
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> parent of ebdb5c6 (reverse)
=======
    const auto loop_time = steady_clock::now();
    bool can_accept = connections.size() < static_cast<size_t>(MAX_SOCKETS - 11);
    m_poller.mod_fd(m_https_socket, can_accept, false);

    const auto events = m_poller.get_events(!connections.empty());
>>>>>>> parent of 02818c2 (threadpooled the connection handling event loop)
<<<<<<< HEAD
=======
    pool_cv.notify_one();
>>>>>>> parent of a8b46b4 (reverting)
=======
>>>>>>> parent of 505c7de (TCP)
=======
>>>>>>> parent of ebdb5c6 (reverse)
    
    //sanity(events);
    
<<<<<<< HEAD
    {
        std::unique_lock<std::mutex> lk(mut);
        loop_cv.wait(lk, [&]{ return threads_finished == thread_vec.size()+1;});
    }
=======
    for (const auto& event : events) {
        std::visit(overloaded {
            [&](node_ptr arg) {
                file_assert(arg != connections.end(), "fd = end");
                if(arg->handle_connection(event, loop_time)) {
                    connections.erase(arg);
                }
            },
            [&](static_fd arg) {
                try {
                    switch (arg) {
                        case static_fd::https_acceptor:
                            accept_connection(m_https_socket,
                                              loop_time,
                                            [] {
                                auto x = std::make_unique<fbw::TLS>();
                                x->next = std::make_unique<fbw::HTTP>(fbw::rootdir, false);
                                return x;
                            });
                            break;
                        case static_fd::http_acceptor:
                            accept_connection(m_redirect_socket,
                                              loop_time,
                                        [] {
                                return std::make_unique<fbw::HTTP>(fbw::rootdir, true);
                            });
                            break;
                        default:
                            break;
                    }
                } catch(const std::runtime_error& e) {
                    logger << e.what() << std::endl;
                }
            }
        }, event.node);
>>>>>>> parent of 02818c2 (threadpooled the connection handling event loop)

    }
    
    const auto sentinel_stale = find_if_not(connections.crbegin(), connections.crend(),
                                   [&](const auto& elem){
        return loop_time - elem.m_time_set > 5s; });
    connections.erase(sentinel_stale.base(), connections.end());
}



/*
 Add new connections to the connection list
 */
void server::accept_connection(const server_socket& sock, tp loop_time,
                               std::function<std::unique_ptr<receiver>()> receiver_stack) {
    
    struct sockaddr_storage cli_addr;
    socklen_t sin_len = sizeof(cli_addr);
    auto skt = sock.accept((sockaddr *) &cli_addr, &sin_len);
    skt.fcntl(F_SETFL, O_NONBLOCK);

<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
<<<<<<< HEAD
=======
>>>>>>> parent of ebdb5c6 (reverse)
    //std::lock_guard lk(m_mut);
    m_connections.emplace_front(loop_time, receiver_stack(), &m_poller, std::move(skt));
    m_poller.add_fd(m_connections.front().m_socket, m_connections.begin(), true, false);
=======

    connections.emplace_front(loop_time, receiver_stack(), &m_poller, std::move(skt));
    
    m_poller.add_fd(connections.front().m_socket, connections.begin(), true, false);
>>>>>>> parent of 02818c2 (threadpooled the connection handling event loop)
<<<<<<< HEAD
=======
    std::lock_guard lk(mut);
    connections.emplace_front(loop_time, receiver_stack(), &m_poller, std::move(skt));
    m_poller.add_fd(connections.front().m_socket, connections.begin(), true, false);
>>>>>>> parent of a8b46b4 (reverting)
=======
    //std::lock_guard lk(m_mut);
    m_connections.emplace_front(loop_time, receiver_stack(), &m_poller, std::move(skt));
    m_poller.add_fd(m_connections.front().m_socket, m_connections.begin(), true, false);
>>>>>>> parent of 505c7de (TCP)
=======
>>>>>>> parent of ebdb5c6 (reverse)

}

server::~server() {
    logger << "~server()" << std::endl;
}


static volatile void* donothing;
void server::sanity(const std::vector<fpollfd> events) {
    
<<<<<<< HEAD
    {
        std::lock_guard lk(mut);
        done = true;
    }
    pool_cv.notify_one();
    for(auto& th : thread_vec) {
        th.join();
    }
    logger << "~server()" << std::endl;
}
=======
    // this cannot create undefined behaviour that didn't already exist and it
    // has some chance of catching it so why not.
    for(auto it = connections.cbegin(); it != connections.cend(); it++) { donothing = &it; }
    logger << "connections not corrupted" << std::endl;
    
    
    for(const auto& event : events) {
        
        if(!std::holds_alternative<node_ptr>(event.node)) {
            continue;
        }
        auto event_node = std::get<node_ptr>(event.node);

        file_assert(event_node != connections.cend(), "end event polled"); 
        
        file_assert(event.read or event.write, "polled event neither for read nor write");
        
        
        
        bool found = false;
        for(auto it = connections.cbegin(); it != connections.cend(); it++) {
            if(event_node == it) {
                found = true;
                break;
            }
        }
        file_assert(found, "unknown event polled");
        
        if( event_node->activity == status::closing ) {
            file_assert(!event.read, "closing connection polled for read");
            file_assert(event.write, "closing connection polled but not for write");
        }

    }
    for(const auto& c : connections) {
        file_assert(c.activity != status::closed, "closed socket polled");
    }
>>>>>>> parent of 02818c2 (threadpooled the connection handling event loop)

    logger << "connections OK" << std::endl;
}

} // namespace fbw
