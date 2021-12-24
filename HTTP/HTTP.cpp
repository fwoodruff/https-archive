//
//  http_connection.cpp
//  piformserver
//
//  Created by Frederick Benjamin Woodruff on 24/07/2021.
//

#include "HTTP.hpp"
#include "http_handler.hpp"
#include "string_utils.hpp"
#include "global.hpp"

#include <iostream>
#include <memory>

namespace fbw {

HTTP::HTTP(std::string folder) : m_folder(folder) {}



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
            file_assert(delimiter == "" or size == 0, "delimiter == "" or size == 0");
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
            logger << "-----------------------------\n";
            logger << "Client header:" << std::endl;
            logger << header << std::endl;
            logger << "body size extracted: " << body.size() << std::endl;
            logger << "-----------------------------\n";
            
            std::string response = respond(m_folder, std::move(header), std::move(body));
            
            output.m_response = to_unsigned(response);
            output.m_status = status::read_only;
        }
    } catch(const http_error& e) {
        logger << e.what() << std::endl;
        header = "";
        output.m_response = to_unsigned(std::string(e.what()) + "\r\n");
        output.m_status = status::closing;
    }
    return output;
}

 
};// namespace fbw
