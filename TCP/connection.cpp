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




// on connection, check user IP and if too many connections in past min send "429 Too Many Requests"

namespace fbw {

// tidy this up with all arguments
connection_base::connection_base() :
    activity(connection_state::live), old_read_state(true), old_write_state(false) {
        read_buffer.resize(BUFFER_SIZE);
}


connection_base::~connection_base() {
    if(context != nullptr) {
        try {
            context->del_fd(m_socket);
        } catch(std::system_error e) {
            std::cerr << e.what() << std::endl;
        }
    }
}

// handle OOB

void connection_base::read_some() {
    if(activity != connection_state::live) {
        return;
    }
    const auto remaining_buffer = read_buffer.size() - read_buffer_end;
    if(remaining_buffer == 0) {
        return;
    }
    assert(read_buffer_end < read_buffer.size());
    assert(remaining_buffer != 0);
    const auto bytes = m_socket.recv(&read_buffer[read_buffer_end], remaining_buffer, 0);
    if (bytes == 0) {
        activity = connection_state::closed;
    } else {
        read_buffer_end += bytes;
        assert(bytes <= remaining_buffer);
        assert(read_buffer_end <= read_buffer.size());
    }
}

/*
 void write_more() {
 }
 
 */

void connection_base::write_some() {
    if(activity == connection_state::closed) {
        return;
    }
    while(!write_buffer.empty()) {
        const auto vec = write_buffer.front();
        size_t bytes = 0;
        [[maybe_unused]] bool passthrough = false;
        if(vec.size() != 0) {
            assert(vec.size() > vec_start); // check this
            try {
                bytes = m_socket.send(&vec[vec_start], vec.size()-vec_start, 0);
            } catch (std::system_error e) {
                if(e.code().value() == EWOULDBLOCK or e.code().value() == EAGAIN) {
                    // polled sockets shouldn't block
                    assert(passthrough == true);
                    break;
                } else {
                    throw;
                }
            }
            // this control flow requires some thought given the object lifetimes
            bytes_queued_for_write -= bytes;
            vec_start += bytes;
            passthrough = true;
        }
        if(vec_start == vec.size()) {
            vec_start = 0;
            write_buffer.pop();
        }
    }
    if(write_buffer_empty() and activity == connection_state::closing) {
        activity = connection_state::closed;
    }
}

void connection_base::send_tcp_close_signal() {
    activity = write_buffer_empty() ? connection_state::closed : connection_state::closing;
}

void connection_base::send_tcp_kill_signal() {
    activity = connection_state::closed;
}

void connection_base::read_bytes(ustring& vec) {
    assert(activity == connection_state::live);
    assert(read_buffer_end <= read_buffer.size());
    std::cout << "READ BYTES:\n";
    for(int i = 0; i < read_buffer_end; i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << int(read_buffer[i]);
    }
    std::cout << std::endl;
    vec.append(&read_buffer[0], &read_buffer[read_buffer_end]);
    read_buffer_end = 0;
}

ssize_t connection_base::send_bytes(ustring bytes) {
    assert(activity != connection_state::closed);
    std::cout << "SEND BYTES:\n";
    for(auto c : bytes) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << int(c);
    }
    std::cout << std::endl;
    write_buffer.push(std::move(bytes));
    bytes_queued_for_write += bytes.size();
    return bytes_queued_for_write;
}

bool connection_base::read_buffer_empty() noexcept {
    return read_buffer_end == 0;
}
bool connection_base::read_buffer_full() noexcept {
    return read_buffer_end == read_buffer.size();
}
bool connection_base::write_buffer_empty() {
    return write_buffer.empty();
}



} // namespace fbw
