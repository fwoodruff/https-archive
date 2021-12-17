
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
#if __linux__
poll_context::poll_context() {
    m_epfd = epoll_create(MAX_SOCKETS);
    if(m_epfd == -1) {
        throw std::system_error(errno, std::generic_category());
    }
}

poll_context::~poll_context() {
    close(m_epfd);
}

void poll_context::add_fd(const cppsocket& sock, node_ptr return_object, bool read_state, bool write_state) {
    epoll_event event;
    event.events = ( read_state ? EPOLLIN : 0) | (write_state ? EPOLLOUT : 0);
    static_assert(sizeof(event.data.ptr) >= sizeof(return_object));
    static_assert(std::is_trivially_copyable<node_ptr>());
    std::memcpy(&event.data.ptr, &return_object,sizeof(return_object));
    if(epoll_ctl(m_epfd, EPOLL_CTL_ADD, sock.get_native(), &event) == -1) {
        assert(errno != EBADF);
        assert(errno != EEXIST);
        assert(errno != EINVAL);
        assert(errno != ELOOP);
        assert(errno != ENOENT);
        assert(errno != EPERM);
        throw std::system_error(errno, std::generic_category());
    }
}

void poll_context::mod_fd(const cppsocket& sock, node_ptr return_object, bool read_state, bool write_state) {
    epoll_event event;
    event.events = ( read_state ? EPOLLIN : 0) | (write_state ? EPOLLOUT : 0);
    static_assert(sizeof(event.data.ptr) >= sizeof(return_object));
    static_assert(std::is_trivially_copyable<node_ptr>());
    std::memcpy(&event.data.ptr,&return_object,sizeof(return_object));
    if(epoll_ctl(m_epfd, EPOLL_CTL_MOD, sock.get_native(), &event) == -1) {
        assert(errno != EBADF);
        assert(errno != EEXIST);
        assert(errno != EINVAL);
        assert(errno != ELOOP);
        assert(errno != ENOENT);
        assert(errno != EPERM);
        throw std::system_error(errno, std::generic_category());
    }
}

void poll_context::del_fd(const cppsocket& sock) {

    if(epoll_ctl(m_epfd, EPOLL_CTL_DEL, sock.get_native(), nullptr)) {
        assert(errno != EBADF);
        assert(errno != EEXIST);
        assert(errno != EINVAL);
        assert(errno != ELOOP);
        assert(errno != ENOENT);
        assert(errno != EPERM);
        throw std::system_error(errno, std::generic_category());
    }
}


std::vector<fpollfd> poll_context::get_events(bool do_timeout) {
    std::vector<fpollfd> events;
    std::vector<epoll_event> epoll_events;
    epoll_events.resize(MAX_SOCKETS);
    const int num_descriptors = epoll_wait(m_epfd, epoll_events.data(), MAX_SOCKETS, do_timeout? timeoutms: -1);
    if (num_descriptors == -1) {
        assert(errno != EBADF);
        assert(errno != EFAULT);
        assert(errno != EINVAL);
        if(errno == EINTR) {
            return events;
        }
        throw std::system_error(errno, std::generic_category());
    }
    events.resize(num_descriptors);
    
    for(int i = 0; i < std::min(num_descriptors, MAX_SOCKETS); i++) {
        events[i].read  = bool(epoll_events[i].events & EPOLLIN );
        events[i].write = bool(epoll_events[i].events & EPOLLOUT);
        std::memcpy(&events[i].node, &epoll_events[i].data.ptr, sizeof (events[i].node));
    }
    return events;
}

#else

poll_context::poll_context() { }
poll_context::~poll_context() { }

void poll_context::add_fd(const cppsocket& sock, node_ptr return_object, bool read_state, bool write_state) {
    auto succ = m_events.insert({sock.get_native(),{return_object, read_state,write_state}});
    assert(succ.second == 1);
}

void poll_context::mod_fd(const cppsocket& sock, node_ptr return_object, bool read_state, bool write_state) {
    auto succ = m_events.erase(sock.get_native());
    if(succ == 0) {
        throw std::logic_error("File descriptor did not exists\n");
    }
    m_events.insert({sock.get_native(),{return_object, read_state,write_state}});
}

void poll_context::del_fd(const cppsocket& sock) {
    long succ = m_events.erase(sock.get_native());
    if (succ == 0) {
        throw std::runtime_error("File descriptor did not exists\n");
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
        assert(errno != EFAULT);
        if(errno == EINTR) {
            return events;
        }
        throw std::system_error(errno, std::generic_category());
    }
    events.reserve(num_descriptors);
    for(const auto& pfd : evs) {
        if(pfd.revents & (POLLIN | POLLOUT)) {
            fpollfd out_event {.read = false, .write = false};
            assert(m_events.find(pfd.fd) != m_events.end());
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
