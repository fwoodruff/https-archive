//
//  server.cpp
//
//  Created by Frederick Benjamin Woodruff on 12/07/2021.
//


#include "connection.hpp"
#include "cppsocket.hpp"
#include "server.hpp"
#include "global.hpp"

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
    
   
    if(::getaddrinfo(nullptr, service.c_str(), &hints, &ai) != 0) {
        throw std::system_error(errno, std::generic_category());
    }

    for(p = ai; p != nullptr; p = p->ai_next) {
        try {
            listener = server_socket(p->ai_family, p->ai_socktype, p->ai_protocol);
            
            int yes;
            listener.setsockopt(SOL_SOCKET, SO_REUSEADDR, &(yes=1), sizeof(int));
            listener.bind(p->ai_addr, p->ai_addrlen);
        } catch ( std::system_error e ) {
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
server::server(std::function<std::unique_ptr<connection_base>()> ctor, std::string service) : m_ctor(ctor) {
    m_sock = get_listener_socket(service.c_str());
    m_poller.add_fd(m_sock, connections.end(), true, false);
    m_sock_can_accept = true;
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
void server::serve_some() {
    std::cout << "num connections: " << connections.size() << std::endl;
    const auto loop_time = steady_clock::now();
    const bool sockaccept = connections.size() < MAX_SOCKETS - 11;
    if(m_sock_can_accept != sockaccept) {
        m_poller.mod_fd(m_sock, connections.end(), sockaccept, false);
        m_sock_can_accept = sockaccept;
    }
    const auto events = m_poller.get_events(!connections.empty());
    clist active;
    for (const auto& event : events) {
        if(event.node == connections.end()) {
            try {
                accept_connection(loop_time);
            } catch(std::system_error e) {
                std::cerr << e.what() << std::endl;
            }
        } else {
            clist x = handle_event(event, loop_time);
            active.splice(begin(active), x);
        }
    }
    const auto sentinel_stale = find_if_not(rbegin(connections), rend(connections),
                                   [&](const auto& elem){
        return loop_time - elem->m_time_set > 5s; });
    
    const auto sentinel_close = partition(begin(active), end(active),
                          [](const auto& client){
        if(client->activity == connection_state::live) {
            client->handle_connection();
        }
        return client->activity != connection_state::closed;
    });
    
    for(auto cli = begin(active); cli != sentinel_close; cli++) {
        assert((*cli)->activity != connection_state::closed);
        auto rs = !(*cli)->read_buffer_full() and ((*cli)->activity == connection_state::live);
        auto ws = !(*cli)->write_buffer_empty();
        if(rs != (*cli)->old_read_state or ws != (*cli)->old_write_state) {
            m_poller.mod_fd((*cli)->m_socket, cli, rs, ws);
            (*cli)->old_read_state = rs;
            (*cli)->old_write_state = ws;
        }
    }
    connections.splice(connections.begin(), active, active.begin(), sentinel_close);
    connections.erase(sentinel_stale.base(), end(connections));
}

/*
 Handle I/O for polled sockets
 */
server::clist server::handle_event(fpollfd event, tp loop_time) noexcept {
    clist single_node_holder;
    single_node_holder.splice(begin(single_node_holder), connections, event.node, next(event.node));
    const auto& client = *event.node;
    try {
        if(event.read) {
            client->read_some();
        }
        if(event.write) {
            client->write_some();
        }
    } catch(std::runtime_error e) {
        client->activity = connection_state::closed;
    }
    client->m_time_set = loop_time;
    return single_node_holder;
}

/*
 Add new connections to the connection list
 */
void server::accept_connection(tp loop_time) {
    clist single_node_holder;
    single_node_holder.emplace_back(m_ctor());
    const auto& node = single_node_holder.back();
    node->m_time_set = loop_time;
    
    struct sockaddr_storage cli_addr;
    socklen_t sin_len = sizeof(cli_addr);
    node->m_socket = m_sock.accept((sockaddr *) &cli_addr, &sin_len);
    node->m_socket.fcntl(F_SETFL, O_NONBLOCK);
    
    m_poller.add_fd(node->m_socket, single_node_holder.begin(), true, false);
    node->context = &m_poller;
    
    // keep new connections on the stack until fully initialised
    connections.splice(connections.begin(), single_node_holder);
}

server::~server() {

}

} // namespace fbw
