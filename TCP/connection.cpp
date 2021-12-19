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
connection::connection() :
activity(status::read_only), primary_receiver(nullptr) {
        
}

void connection::push_receiver(std::unique_ptr<receiver>&& r) {
    if(primary_receiver != nullptr) {
        r->next = std::move(primary_receiver);
    }
    primary_receiver = std::move(r);
}


connection::~connection() {
    if(context != nullptr) {
        try {
            context->del_fd(m_socket);
        } catch(std::system_error e) {
            std::cerr << e.what() << std::endl;
        }
    }
}


// handle OOB


void connection::send_bytes_over_network() {
    switch(activity) {
        case status::read_only:
        case status::always_poll:
        //case status::dormant:
        case status::closing:
            break;
        case status::closed:
            assert(false);
            return;
    }
    
    auto bytes = m_socket.send(write_buffer.data(), write_buffer.size(), 0);
    if(bytes == write_buffer.size()) {
        write_buffer.clear();
    } else {
        write_buffer = write_buffer.substr(bytes);
    }
    if(write_buffer.empty() and activity == status::closing) {
        activity = status::closed;
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
    std::cout << "READ BYTES:\n";
    for(int i = 0; i < bytes; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << int(out[i]);
    }
    std::cout << std::endl;
    out.resize(bytes);
    return out;
}

ssize_t connection::queue_bytes_for_write(ustring bytes) {
    std::cout << "SEND BYTES:\n";
    for(auto c : bytes) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << int(c);
    }
    std::cout << std::endl;
    write_buffer.append(bytes);

    return write_buffer.size();
}

bool connection::handle_connection(fpollfd event, time_point<steady_clock,nanoseconds> loop_time) noexcept {
    try {
        assert(primary_receiver != nullptr);
        switch(activity) {
            case status::read_only:
            //case status::dormant:
                if(event.read) {
                    ustring out = receive_bytes_from_network();
                    auto st_msg = primary_receiver->handle(out);
                    activity = st_msg.m_status;
                    write_buffer.append(st_msg.m_response);
                }
                if(event.write) {
                    send_bytes_over_network();
                }
                break;
            case status::always_poll:
                if(write_buffer.empty()) {
                    if(event.read) {
                        ustring out = receive_bytes_from_network();
                        
                        auto st_msg = primary_receiver->handle(out);
                        activity = st_msg.m_status;
                    }
                }
                if(event.write) {
                    send_bytes_over_network();
                }
                break;
            case status::closing:
                if(event.write) {
                    send_bytes_over_network();
                }
                break;
            case status::closed:
                assert(false);
                
        }
    } catch(std::runtime_error e) {
        activity = status::closed;
    }

    m_time_set = loop_time;
    
    bool poll_for_read =  (activity ==  status::read_only) or
                          (activity == status::always_poll and write_buffer.empty());
    bool poll_for_write = (!write_buffer.empty() and activity != status::closed) or
                          (activity == status::always_poll and write_buffer.empty());

    
    context->mod_fd(m_socket, event.node, poll_for_read, poll_for_write);
    return activity == status::closed;
}







} // namespace fbw
