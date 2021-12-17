//
//  cppsocket.hpp
//  piserver
//
//  Created by Frederick Benjamin Woodruff on 13/07/2021.
//

#ifndef cppsocket_hpp
#define cppsocket_hpp

#include <sys/socket.h>
#include <sys/types.h>
#include <system_error>

#include <memory>




namespace fbw{



using fd_t = int;

class cppsocket {
protected:
    fd_t m_fd;
    cppsocket(fd_t fd) noexcept;
    cppsocket(int domain, int type, int protocol);
    cppsocket() noexcept;
public:
    //static const ssize_t max_n = 5000;
    
    virtual ~cppsocket();
    cppsocket(const cppsocket& other) = delete;
    cppsocket& operator=(const cppsocket& other) = delete;
    cppsocket(cppsocket&& other) noexcept;
    cppsocket& operator=(cppsocket&& other) noexcept ;
    
    void getsockopt(int level, int optname, void *optval, socklen_t *optlen) const;
    void setsockopt(int level, int optname, const void *optval, socklen_t optlen) const;
    size_t send(const void *buf, size_t len, int flags) const;
    size_t recv(void *buf, size_t len, int flags) const;
    
    fd_t get_native() const;

    friend bool operator== (const cppsocket &lhs, const cppsocket &rhs);
    friend bool operator< (const cppsocket &lhs, const cppsocket &rhs);

    int fcntl(int cmd...) const;

    friend class std::hash<cppsocket>;
    
};


class client_socket final : public cppsocket {
public:
    client_socket() : cppsocket() {}
    client_socket(int fd) : cppsocket(fd) {}
    client_socket(int domain, int type, int protocol) : cppsocket(domain, type, protocol) {}
    
    void connect(const struct sockaddr *addr, socklen_t addrlen) const;
    std::pair<std::string, std::string> cli_socketinfo();
    friend class server_socket;
    friend class std::hash<client_socket>;
};


class server_socket final : public cppsocket {
public:
    std::string name;
    server_socket() : cppsocket() {}
    server_socket(int fd) : cppsocket(fd) {}
    server_socket(int domain, int type, int protocol) : cppsocket(domain, type, protocol) {}
    
    void bind(const struct sockaddr *addr, socklen_t addrlen) const;
    client_socket accept(sockaddr * addr, socklen_t *addrlen) const;
    void listen(int backlog) const;
    std::string serv_socketinfo();
    friend class std::hash<server_socket>;
};


} // namespace fbw


template<> struct std::hash<fbw::cppsocket> { // does this slice anything?
    std::size_t operator()(const fbw::cppsocket& sock) const noexcept
    {
        return std::hash<int>{}(sock.m_fd);
    }
};





#endif /* cppsocket_hpp */
