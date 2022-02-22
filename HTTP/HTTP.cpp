//
//  HTTP.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 24/07/2021.
//

#include "HTTP.hpp"
#include "http_handler.hpp"
#include "string_utils.hpp"
#include "global.hpp"

#include <iostream>
#include <sstream>
#include <memory>


namespace fbw {

HTTP::HTTP(std::string folder, bool redirect) : m_folder(folder), m_redirect(redirect) {}



/*
 This gets called when there is data in https_connection::input to handle
 */
status_message HTTP::handle(ustring uinput) noexcept {
    std::string input = to_signed(std::move(uinput));
    status_message output;
    try {
        // loop
        if(input.size() > max_bytes_queued) {
            throw http_error("414 URI Too Long");
        }
        if(header.empty()) {
            header = extract(input, "\r\n\r\n");
        }
        
        if(!header.empty()) {
            const auto [delimiter, size] = body_size(header);
            file_assert(delimiter == "" or size == 0, "no delimiter or size == 0");
            std::string body;
            if(delimiter != "") {
                body += extract(input, delimiter);
                throw http_error("418 I'm a teapot");
                // I need to implement this
            } else if(size != 0) {
                body += extract(input, size);
                if(body.size() == 0) {
                    return {to_unsigned(""), status::read_only};
                }
            }
            
            std::string response;
            
            if(m_redirect) {
                response = redirect(std::move(header), domain_name);
            } else {
                response = respond(m_folder, std::move(header), std::move(body));
            }
            header.clear();

            output.m_response = to_unsigned(response);
            output.m_status = status::read_only;
        }
    } catch(const http_error& e) {
        header = "";
        
        auto error_message = std::string(e.what());
        
        std::ostringstream oss;
        oss << "HTTP/1.1 " << error_message << "\r\n"
        << "Connection: close\r\n"
        << "Content-Type: text/html; charset=UTF-8\r\n"
        << "Content-Length: " << error_message.size() << "\r\n"
        << "Server: FredPi/0.1 (Unix) (Raspbian/Linux)\r\n"
        << "\r\n"
        << error_message;
        output.m_response = to_unsigned(oss.str());
        output.m_status = status::closing;
        
    }
    return output;
}

 
};// namespace fbw
