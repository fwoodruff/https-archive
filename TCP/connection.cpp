//
//  connection.cpp
//  HTTPS Server
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
    write_buffer {},
    m_time_set(tp),
    context(ctx),
    m_socket(std::move(socket)),
    primary_receiver (std::move(rcv)),
    activity(status::read_write),
    old_read(true),
    old_write(false)
{

}

void connection::push_receiver(std::unique_ptr<receiver> r) {
    if(primary_receiver != nullptr) {
        r->next = std::move(primary_receiver);
    }
    primary_receiver = std::move(r);
}


connection::~connection() {
    if(context != nullptr) {
        try {
            context->del_fd(m_socket);
        } catch(const std::system_error& e) {
            file_assert(false, e.what());
        }
    }
}




void connection::send_bytes_over_network() {
    switch(activity) {
        case status::read_write:
        case status::flush:
        //case status::dormant:
        case status::closing:
            break;
        case status::closed:
            file_assert(false, "cannot send bytes over closed connection");
            return;
    }

    if(write_buffer.empty()) {
        logger << "sending empty buffer\n";
    }

    

    
    auto bytes = m_socket.send(write_buffer.data(), write_buffer.size(), MSG_NOSIGNAL);
    file_assert(bytes <= write_buffer.size(), "bytes <= write_buffer.size()");
    if(bytes == 0) {
        logger << "sent no bytes\n" << std::flush;
    }
    
    if(bytes == write_buffer.size()) {
        write_buffer.clear();
    } else {
        auto tmp = write_buffer.substr(bytes);
        write_buffer = tmp;
    }
    if(write_buffer.empty() and activity == status::closing) {
        activity = status::closed;
    }

    if(write_buffer.size() > 2000000) {
        throw std::runtime_error("too much requested");
    }
    
}

ustring connection::receive_bytes_from_network() {
    ustring out;
    out.resize(BUFFER_SIZE);
    const auto bytes = m_socket.recv(out.data(), out.size(), 0);
    if (bytes == 0) {
        activity = status::closed;
        throw std::runtime_error("closing connection");
    }
    out.resize(bytes);
    return out;
}

ssize_t connection::queue_bytes_for_write(ustring bytes) {
    write_buffer.append(bytes);
    return write_buffer.size();
}

bool connection::handle_connection(fpollfd event, time_point<steady_clock,nanoseconds> loop_time) {
    // nothing useful has happened if:
    // no data sent
    // no data received
    //
    
    try {
        file_assert(primary_receiver != nullptr, "bad primary receiver");
        switch(activity) {
            case status::read_write:
                logger << "read write\n";
            //case status::dormant:
                file_assert(event.read or event.write, "shouldn't be polled if nothing to read or write");
                if(event.read) {
                    ustring out = receive_bytes_from_network();
                    auto st_msg = primary_receiver->handle(std::move(out));
                    activity = st_msg.m_status;
                    write_buffer.append(st_msg.m_response);
                }
                if(event.write) {
                    send_bytes_over_network();
                }
                break;
            case status::flush:
            {
                file_assert(!event.read, "cannot read while flushing buffer");
                file_assert(event.write, "writing to unwriteable socket");
                logger << "flush\n";
                auto st_msg = primary_receiver->handle({});
                activity = st_msg.m_status;
                write_buffer.append(st_msg.m_response);
                send_bytes_over_network();
            }
                break;
            
            case status::closing:
                file_assert(!event.read, "closing socket polled for read");
                file_assert(event.write, "writing to unwriteable");
                send_bytes_over_network();
                
                
                break;
            case status::closed:
                file_assert(false, "closed socket polled");
                
        }
    } catch(const std::runtime_error& e) {
        logger << "exception" << std::endl;
        logger << e.what() << std::endl;
        activity = status::closed;
    } catch(...) {
        file_assert(false, "uncaught exception in handle_connection");
    }
    

    m_time_set = loop_time;
    
<<<<<<< HEAD
<<<<<<< HEAD
    logger << "end of handle connection\n";
    return m_activity == status::closed;
=======
    
    
    bool poll_for_read  = (activity ==  status::read_only) or
                          (activity == status::write_only and write_buffer.empty());
    bool poll_for_write = activity != status::closed and (!write_buffer.empty() or
                          (activity == status::write_only and write_buffer.empty()));
    // fix me
    context->mod_fd(m_socket, poll_for_read, poll_for_write);
    
    
    if(activity == status::closed) {
        file_assert(!poll_for_read, "polling for read on about to be deleted connection");
        file_assert(!poll_for_write, "polling for write on about to be deleted connection");
    }
    
    if(activity == status::closing) {
        file_assert(!poll_for_read, "polling for read on closing socket");
    }
    
    return activity == status::closed;
>>>>>>> parent of 02818c2 (threadpooled the connection handling event loop)
=======
    return activity == status::closed;
>>>>>>> parent of a8b46b4 (reverting)
}







} // namespace fbw
