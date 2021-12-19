//
//  cppsocket.cpp
//  piserver
//
//  Created by Frederick Benjamin Woodruff on 13/07/2021.
//

#include "cppsocket.hpp"

#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include <iostream>
#include <sstream>
#include <cassert>

namespace fbw {
bool operator== (const cppsocket &lhs, const cppsocket &rhs) {
    return lhs.m_fd == rhs.m_fd;
}
bool operator< (const cppsocket &lhs, const cppsocket &rhs) {
    return lhs.m_fd < rhs.m_fd;
}

int cppsocket::get_native() const {
    return m_fd;
}

cppsocket::~cppsocket() {
    if(m_fd != -1) {
        std::cout << "closing socketfd: " << m_fd << std::endl;
        ::close(m_fd);
    }
};


cppsocket::cppsocket() noexcept : m_fd(-1) { }

cppsocket::cppsocket(int _fd) noexcept :
    m_fd(_fd) { }

cppsocket::cppsocket(int domain, int type, int protocol) :
    cppsocket(::socket(domain, type, protocol)) {}

cppsocket::cppsocket(cppsocket&& other) noexcept {
    *this = std::move(other);
}

cppsocket& cppsocket::operator=(cppsocket&& other) noexcept {
    m_fd = std::exchange(other.m_fd, -1);
    return *this;
}
       
client_socket server_socket::accept(sockaddr * addr, socklen_t *addrlen) const {
    assert(m_fd != -1);
    const fd_t sock = ::accept(m_fd, addr, addrlen);
    std::cout << "accepting socketfd: " << sock << std::endl;
    if(sock == -1) {
        assert(errno != EBADF);
        assert(errno != EFAULT);
        assert(errno != ENOTSOCK);
        assert(errno != EOPNOTSUPP);
        assert(errno != EINVAL);
        throw std::system_error(errno, std::generic_category());
    }
    return client_socket(sock);
}
void client_socket::connect( const sockaddr *addr, socklen_t addrlen) const {
    assert(m_fd != -1);
    if(::connect(m_fd, addr, addrlen)==-1) {
        throw std::system_error(errno, std::generic_category());
    }
}
void cppsocket::getsockopt(int level, int optname, void *optval, socklen_t *optlen) const {
    assert(m_fd != -1);
    if(::getsockopt(m_fd, level, optname, optval, optlen) == -1) {
       throw std::system_error(errno, std::generic_category());
    }
}
void cppsocket::setsockopt(int level, int optname, const void *optval, socklen_t optlen) const {
    assert(m_fd != -1);
    if(::setsockopt(m_fd, level, optname, optval, optlen) == -1) {
        throw std::system_error(errno, std::generic_category());
    }
}
size_t cppsocket::send(const void *buf, size_t len, int flags) const {
    assert(m_fd != -1);
    const ssize_t bytes = ::send(m_fd , buf, len, flags);
    if(bytes == -1) {
        throw std::system_error(errno, std::generic_category());
    }
    return bytes;
}

size_t cppsocket::recv(void *buf, size_t len, int flags) const {
    assert(m_fd != -1);
    const ssize_t bytes = ::recv(m_fd, buf, len, flags);
    if(bytes == -1) {
        throw std::system_error(errno, std::generic_category());
    }
    return bytes;
}


void server_socket::bind(const sockaddr *addr, socklen_t addrlen) const {
    assert(m_fd != -1);
    if(::bind(m_fd, addr, addrlen) == -1) {
        throw std::system_error(errno, std::generic_category());
    }
}

void server_socket::listen(int backlog) const {
    assert(m_fd != -1);
    if(::listen(m_fd,backlog) == -1) {
        throw std::system_error(errno, std::generic_category());
    }
}

int cppsocket::fcntl(int cmd...) const {
    assert(m_fd != -1);
    auto x = ::fcntl(m_fd, cmd);
    if(x == -1) {
        throw std::system_error(errno, std::generic_category());
    }
    return x;
}

std::string server_socket::serv_socketinfo() {
    return name;
}

std::pair<std::string,std::string> client_socket::cli_socketinfo() {
    socklen_t sin_len;
    struct sockaddr_storage cli_addr;
    char ipstr[INET6_ADDRSTRLEN];
    int port;
    
    char host[1024];
    char service[32];
    
    sin_len = sizeof cli_addr;

    getpeername(m_fd, (struct sockaddr*)&cli_addr, &sin_len);

    int code = ::getnameinfo((const struct sockaddr *)&cli_addr,
                             sin_len, host, sizeof(host), service, sizeof service, 0);
    if(code != 0) {
        throw std::runtime_error(std::string(gai_strerror(code)));
    }

    if (cli_addr.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&cli_addr;
        port = ntohs(s->sin_port);
        if(inet_ntop(AF_INET, &s->sin_addr, ipstr, sizeof ipstr) == nullptr) {
            throw std::system_error(errno, std::generic_category());
        }
    } else {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&cli_addr;
        port = ntohs(s->sin6_port);
        if( inet_ntop( AF_INET6, &s->sin6_addr, ipstr, sizeof ipstr)==nullptr) {
            throw std::system_error(errno, std::generic_category());
        }
    }
    
    std::ostringstream oss;
    oss << std::string(host)
        << " " << std::string(ipstr) << ", "
        << service << " [" << port << "]";

    return {oss.str(), std::string(ipstr)};
}





} // namespace fbw
