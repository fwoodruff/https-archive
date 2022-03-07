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
            
            int yes = 1;
            listener.setsockopt(SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));
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
    

    unsigned int nthreads = std::thread::hardware_concurrency();
    nthreads = std::clamp(nthreads, 1u, static_cast<unsigned int> (MAX_SOCKETS));
    for(int i = 0; i < nthreads - 1; i++) {
        thread_vec.emplace_back(&server::server_thread_task, this);
    }
    thj.thds = &thread_vec;
    

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

void server::do_task(fpollfd event) {
    std::visit(overloaded {
        [&](node_ptr arg) {
            file_assert(arg != connections.end(), "fd = end");
            bool kill_me = arg->handle_connection(event, loop_time);

            if(kill_me) {
                std::lock_guard lk(mut);
                connections.erase(arg);
            } else {
                bool poll_for_read  = (arg->activity ==  status::read_only) or
                                      (arg->activity == status::write_only and arg->write_buffer.empty());
                bool poll_for_write = arg->activity != status::closed and (!arg->write_buffer.empty() or
                                      (arg->activity == status::write_only));
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
    int idx;
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


void server::serve_some() {
    bool can_accept = connections.size() < static_cast<size_t>(MAX_SOCKETS - 11);
    m_poller.mod_fd(m_https_socket, can_accept, false);
    loop_time = steady_clock::now();
    loop_events = m_poller.get_events(!connections.empty());
    
    events_started = 0;
    threads_finished = 0;
    

    {
        std::lock_guard<std::mutex> lk(mut);
        threads_to_start = thread_vec.size();
    }
    pool_cv.notify_one();
    
    while(get_task()) {}
    
    {
        std::unique_lock<std::mutex> lk(mut);
        loop_cv.wait(lk, [&]{ return threads_finished == thread_vec.size()+1;});
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

    std::lock_guard lk(mut);
    connections.emplace_front(loop_time, receiver_stack(), &m_poller, std::move(skt));
    m_poller.add_fd(connections.front().m_socket, connections.begin(), true, false);

}

server::~server() {
    
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


} // namespace fbw
