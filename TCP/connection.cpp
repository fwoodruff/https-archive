//
//  connect.cpp
//
//  Created by Frederick Benjamin Woodruff on 09/07/2021.
//


#include "connection.hpp"
#include "polling.hpp"
#include "global.hpp"

#include <sys/socket.h>

#include <system_error>
#include <string>
#include <iostream>
#include <vector>
#include <cstddef>
#include <iomanip>
#include <memory>




// on connection, check user IP and if too many connections in past min send "429 Too Many Requests"

namespace fbw {



// tidy this up with all arguments
connection::connection(time_point<steady_clock> tp, std::unique_ptr<receiver> rcv, poll_context* ctx, client_socket socket) :
    m_write_buffer {},
    m_time_set(tp),
    m_poll_context(ctx),
    m_socket(std::move(socket)),
    m_primary_receiver (std::move(rcv)),
    m_activity(status::read_write),
    m_old_read(true),
    m_old_write(false)
{

}

void connection::push_receiver(std::unique_ptr<receiver> r) {
    if(m_primary_receiver != nullptr) {
        r->next = std::move(m_primary_receiver);
    }
    m_primary_receiver = std::move(r);
}


connection::~connection() {
    if(m_poll_context != nullptr) {
        try {
            m_poll_context->del_fd(m_socket);
        } catch(const std::system_error& e) {
            file_assert(false, e.what());
        }
    } else {
        file_assert(false, "closing bad connection");
    }
}




void connection::send_bytes_over_network() {
    switch(m_activity) {
        case status::read_write:
        case status::flush:
        //case status::dormant:
        case status::closing:
            break;
        case status::closed:
            file_assert(false, "cannot send bytes over closed connection");
            return;
    }

    file_assert(!m_write_buffer.empty(), "sending empty buffer");

    
    auto bytes = m_socket.send(m_write_buffer.data(), m_write_buffer.size(), MSG_NOSIGNAL);
    file_assert(bytes <= m_write_buffer.size(), "bytes <= write_buffer.size()");
    if(bytes == 0) {
        logger << "sent no bytes\n" << std::flush;
    }
    
    if(bytes == m_write_buffer.size()) {
        m_write_buffer.clear();
    } else {
        auto tmp = m_write_buffer.substr(bytes);
        m_write_buffer = tmp;
    }
    if(m_write_buffer.empty() and m_activity == status::closing) {
        m_activity = status::closed;
    }

    if(m_write_buffer.size() > 2000000) {
        throw std::runtime_error("too much requested");
    }
    
}

ustring connection::receive_bytes_from_network() {
    ustring out;
    out.resize(BUFFER_SIZE);
    const auto bytes = m_socket.recv(out.data(), out.size(), 0);
    if (bytes == 0) {
        m_activity = status::closed;
        throw std::runtime_error("closing connection");
    }
    out.resize(bytes);
    return out;
}

ssize_t connection::queue_bytes_for_write(ustring bytes) {
    m_write_buffer.append(bytes);
    return m_write_buffer.size();
}

bool connection::handle_connection(fpollfd event, time_point<steady_clock,nanoseconds> loop_time) {
    // nothing useful has happened if:
    // no data sent
    // no data received
    //
    logger << "handle connection\n";
    try {
        file_assert(m_primary_receiver != nullptr, "bad primary receiver");
        switch(m_activity) {
            case status::read_write:
                logger << "read write\n";
            //case status::dormant:
                file_assert(event.m_read or event.m_write, "shouldn't be polled if nothing to read or write");
                if(event.m_read) {
                    ustring out = receive_bytes_from_network();
                    auto st_msg = m_primary_receiver->handle(std::move(out));
                    m_activity = st_msg.m_status;
                    m_write_buffer.append(st_msg.m_response);
                }
                if(event.m_write) {
                    send_bytes_over_network();
                }
                break;
            case status::flush:
            {
                file_assert(!event.m_read, "cannot read while flushing buffer");
                file_assert(event.m_write, "writing to unwriteable socket");
                logger << "flush\n";
                auto st_msg = m_primary_receiver->handle({});
                file_assert(!st_msg.m_response.empty(), "nothing to send");
                
                m_activity = st_msg.m_status;
                m_write_buffer.append(st_msg.m_response);
                send_bytes_over_network();
            }
                break;
            
            case status::closing:
                logger << "closing\n";
                file_assert(!event.m_read, "closing socket polled for read");
                file_assert(event.m_write, "writing to unwriteable");
                send_bytes_over_network();
                file_assert(m_activity == status::closed or m_write_buffer.size() != 0, "bad closing state");
                logger << "write buffer size: " << m_write_buffer.size() << std::endl;
                
                break;
            case status::closed:
                file_assert(false, "closed socket polled");
                
        }
    } catch(const std::runtime_error& e) {
        logger << "exception" << std::endl;
        logger << e.what() << std::endl;
        m_activity = status::closed;
    } catch(...) {
        file_assert(false, "uncaught exception in handle_connection");
    }

    m_time_set = loop_time;
    
    logger << "end of handle connection\n";
    return m_activity == status::closed;
}







} // namespace fbw
