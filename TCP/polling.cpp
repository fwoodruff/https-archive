//
//  polling.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 10/07/2021.
//


#include "polling.hpp"

#include "global.hpp"
#include "connection.hpp"
#include "cppsocket.hpp"



#include <type_traits>
#include <cassert>
#if __linux__
#include <sys/epoll.h>
#include <unistd.h>
#include <cstring>
#endif

namespace fbw {
#ifdef __linux__
/*
 Using epoll is overkill and more useful for proxies and balancers.
 This is a not production code and I wanted to use it anyway.
 */

poll_context::poll_context() {
    m_epfd = epoll_create(MAX_SOCKETS);
    if(m_epfd == -1) {
        throw std::system_error(errno, std::generic_category());
    }
}

poll_context::~poll_context() {
    logger << "closing poll context" << std::endl;
    close(m_epfd);
}

void poll_context::add_fd(const cppsocket& sock, event_var return_object, bool read_state, bool write_state) {
    epoll_event event {};
    event.events = ( read_state ? EPOLLIN : 0) | (write_state ? EPOLLOUT : 0);
    
    int r_fd = sock.get_native();
    
    event.data.fd = r_fd;

    if(epoll_ctl(m_epfd, EPOLL_CTL_ADD, r_fd, &event) == -1) {
        logger << "errno: " << errno << std::endl;
        assert(false);
    } else {
        auto succ = m_events.insert({r_fd, return_object});
        assert(succ.second);
    }
}

void poll_context::mod_fd(const cppsocket& sock, bool read_state, bool write_state) {
    epoll_event event {};
    event.events = ( read_state ? EPOLLIN : 0) | (write_state ? EPOLLOUT : 0);
    int r_fd = sock.get_native();
    event.data.fd = r_fd;
    
    if(epoll_ctl(m_epfd, EPOLL_CTL_MOD, r_fd, &event) == -1) {
        logger << "errno: " << errno << std::endl;
        assert(false);
    }
}

void poll_context::del_fd(const cppsocket& sock) {
    if(epoll_ctl(m_epfd, EPOLL_CTL_DEL, sock.get_native(), nullptr) == -1) {
        logger << "errno: " << errno << std::endl;
        assert(false);
    } else {
        size_t rm = m_events.erase(sock.get_native());
        assert(rm == 1);
    }
}

std::vector<fpollfd> poll_context::get_events(bool do_timeout) {
    std::vector<fpollfd> events;
    std::vector<epoll_event> epoll_events;
    epoll_events.resize(MAX_SOCKETS);
    const int num_descriptors = epoll_wait(m_epfd, epoll_events.data(), MAX_SOCKETS, do_timeout? timeoutms: -1);
    assert(num_descriptors <= MAX_SOCKETS);
    if (num_descriptors == -1) {
        if(errno == EINTR) {
            return events;
        }
        logger << "errno: " << errno << std::endl;
        assert(false);
    }
    events.resize(num_descriptors);
    
    for(int i = 0; i < num_descriptors; i++) {
        events[i].read  = bool(epoll_events[i].events & EPOLLIN );
        events[i].write = bool(epoll_events[i].events & EPOLLOUT);
        assert(m_events.find(epoll_events[i].data.fd) != m_events.end());
        events[i].node = m_events[epoll_events[i].data.fd];
    }
    return events;
}

#else

poll_context::poll_context() { }
poll_context::~poll_context() { }

void poll_context::add_fd(const cppsocket& sock, event_var return_object, bool read_state, bool write_state) {
    auto succ = m_events.insert({sock.get_native(),{return_object, read_state,write_state}});
    assert(succ.second == 1);
}

void poll_context::mod_fd(const cppsocket& sock, bool read_state, bool write_state) {
    assert(m_events.find(sock.get_native()) != m_events.end());
    auto fp = m_events[sock.get_native()];
    auto succ = m_events.erase(sock.get_native());
    
    assert(succ != 0);
    
    fp.read = read_state;
    fp.write = write_state;
    m_events.insert({sock.get_native(), fp});
}

void poll_context::del_fd(const cppsocket& sock) {
    long succ = m_events.erase(sock.get_native());
    if (succ == 0) {
        assert(succ != 0);
    }
}

std::vector<fpollfd> poll_context::get_events(bool do_timeout) {
    std::vector<fpollfd> events {};
    int num_descriptors = 0;
    std::vector<pollfd> evs {};

    for(const auto& [fd, afpollfd] : m_events) {
        short ev = (afpollfd.read ? POLLIN  : 0) |
                   (afpollfd.write ? POLLOUT : 0) ;
        evs.push_back({ .fd = fd, .events = ev});
    }
    
    num_descriptors = poll(evs.data(), (int) evs.size(), do_timeout? timeoutms : -1);
    
    if(num_descriptors == -1) {
        if(errno == EINTR) {
            return events;
        }
        logger << "errno: " << errno << std::endl;
        assert(false);
    }
    events.reserve(num_descriptors);
    for(const auto& pfd : evs) {
        if(pfd.revents & (POLLIN | POLLOUT)) {
            fpollfd out_event {.read = false, .write = false};
            out_event.node = m_events[pfd.fd].node;
            if(pfd.revents & POLLIN)  { out_event.read  = true; }
            if(pfd.revents & POLLOUT) { out_event.write = true; }
            events.push_back(out_event);
        }
        if(events.size() >= static_cast<size_t>(MAX_SOCKETS)) {
            break;
        }
    }
    return events;
}


#endif // linux

} // namespace fbw
