//
//  server.cpp
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
#include <thread>
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
    logger << "get_listener_socket()" << std::endl;
    server_socket listener;
    struct addrinfo hints, *ai, *p;

    memset(&hints,0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;
    
   
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
server::server(std::string service, std::function<std::unique_ptr<receiver>()> receiver_stack) : m_factory(receiver_stack) {
    logger << "server::server()" << std::endl;
    m_sock = get_listener_socket(service.c_str());
    m_poller.add_fd(m_sock, static_fd::acceptor, true, false);
    m_service = service;
    
    
    
    
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
 
 To do:
 Implement resumption of old TLS sessions on new connections.
 This will involve an LRU cache of session keys, but where no IP is allowed multiple entries
 */




template<class... Ts> struct overloaded : Ts... { using Ts::operator()...; };
template<class... Ts> overloaded(Ts...) -> overloaded<Ts...>;

void server::serve_some() {
    logger << "server::serve_some()" << std::endl;
    logger << "number of connections: " << connections.size() << std::endl;
    const auto loop_time = steady_clock::now();
    bool can_accept = connections.size() < static_cast<size_t>(MAX_SOCKETS - 11);
    m_poller.mod_fd(m_sock, can_accept, false);

    const auto events = m_poller.get_events(!connections.empty());
    
    sanity(events);
    
    for (const auto& event : events) {
        std::visit(overloaded {
            [&](node_ptr arg) {
                file_assert(arg != connections.end(), "fd = end");
                if(arg->handle_connection(event, loop_time)) {
                    connections.erase(arg);
                }
            },
            [&](static_fd arg) {
                file_assert(arg == static_fd::acceptor, "bad event");
                try {
                    accept_connection(loop_time);
                } catch(const std::runtime_error& e) {
                    logger << e.what() << std::endl;
                }
            }
        }, event.node);

    }
    
    const auto sentinel_stale = find_if_not(connections.crbegin(), connections.crend(),
                                   [&](const auto& elem){
        return loop_time - elem.m_time_set > 5s; });
    connections.erase(sentinel_stale.base(), connections.end());
}



/*
 Add new connections to the connection list
 */
void server::accept_connection(tp loop_time) {
    logger << "server::accept_connection()" << std::endl;
    
    struct sockaddr_storage cli_addr;
    socklen_t sin_len = sizeof(cli_addr);
    auto skt = m_sock.accept((sockaddr *) &cli_addr, &sin_len);
    skt.fcntl(F_SETFL, O_NONBLOCK);
    
    auto [full_name, ip ] = skt.cli_socketinfo();
    logger << full_name << " ... " << ip << std::endl;

    connections.emplace_front(loop_time, m_factory(), &m_poller, std::move(skt));
    
    m_poller.add_fd(connections.front().m_socket, connections.begin(), true, false);

}

server::~server() {
    logger << "~server()" << std::endl;
}


static volatile void* donothing;
void server::sanity(const std::vector<fpollfd> events) {
    
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
    
    
    
    logger << "connections OK" << std::endl;
}

} // namespace fbw
