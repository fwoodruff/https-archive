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
        file_assert(false, "epoll add failed");
    } else {
        auto succ = m_events.insert({r_fd, return_object});
        file_assert(succ.second, "insertion failed in add_fd");
    }
}

void poll_context::mod_fd(const cppsocket& sock, bool read_state, bool write_state) {
    epoll_event event {};
    event.events = ( read_state ? EPOLLIN : 0) | (write_state ? EPOLLOUT : 0);
    int r_fd = sock.get_native();
    event.data.fd = r_fd;
    
    if(epoll_ctl(m_epfd, EPOLL_CTL_MOD, r_fd, &event) == -1) {
        logger << "errno: " << errno << std::endl;
        file_assert(false, "epoll mod failed");
    }
}

void poll_context::del_fd(const cppsocket& sock) {
    if(epoll_ctl(m_epfd, EPOLL_CTL_DEL, sock.get_native(), nullptr) == -1) {
        logger << "errno: " << errno << std::endl;
        file_assert(false, "epoll del failed");
    } else {
        size_t rm = m_events.erase(sock.get_native());
        file_assert(rm == 1, "removed object wasn't in poll context");
    }
}

std::vector<fpollfd> poll_context::get_events(bool do_timeout) {
    std::vector<fpollfd> events;
    std::vector<epoll_event> epoll_events;
    epoll_events.resize(MAX_SOCKETS);
    const int num_descriptors = epoll_wait(m_epfd, epoll_events.data(), MAX_SOCKETS, do_timeout? timeoutms: -1);
    file_assert(num_descriptors <= MAX_SOCKETS, "too many descriptors retrieved");
    if (num_descriptors == -1) {
        if(errno == EINTR) {
            return events;
        }
        logger << "errno: " << errno << std::endl;
        file_assert(false, "epoll_wait failed");
    }
    events.resize(num_descriptors);
    
    for(int i = 0; i < num_descriptors; i++) {
        events[i].read  = bool(epoll_events[i].events & EPOLLIN );
        events[i].write = bool(epoll_events[i].events & EPOLLOUT);
        file_assert(m_events.find(epoll_events[i].data.fd) != m_events.end(), "polled event did not exist");
        events[i].node = m_events[epoll_events[i].data.fd];
    }
    return events;
}

#else

poll_context::poll_context() { }
poll_context::~poll_context() { }

void poll_context::add_fd(const cppsocket& sock, event_var return_object, bool read_state, bool write_state) {
    auto succ = m_events.insert({sock.get_native(),{return_object, read_state,write_state}});
    file_assert(succ.second == 1, "fd already in context");
}

void poll_context::mod_fd(const cppsocket& sock, bool read_state, bool write_state) {
    file_assert(m_events.find(sock.get_native()) != m_events.end(), "bad mod_fd assert");
    auto fp = m_events[sock.get_native()];
    auto succ = m_events.erase(sock.get_native());
    
    file_assert(succ != 0, "file descriptor didn't exist, mod_fd");
    
    fp.read = read_state;
    fp.write = write_state;
    m_events.insert({sock.get_native(), fp});
}

void poll_context::del_fd(const cppsocket& sock) {
    long succ = m_events.erase(sock.get_native());
    if (succ == 0) {
        file_assert(succ != 0, "file descriptor didn't exist, del_fd");
    }
}

std::vector<fpollfd> poll_context::get_events(bool do_timeout) {
    std::vector<fpollfd> events;
    int num_descriptors;
    std::vector<pollfd> evs;

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
        file_assert(false, "poll failed");
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
        if(events.size() >= MAX_SOCKETS) {
            break;
        }
    }
    return events;
}


#endif // linux

} // namespace fbw
