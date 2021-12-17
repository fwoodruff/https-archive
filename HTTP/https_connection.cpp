//
//  http_connection.cpp
//  piformserver
//
//  Created by Frederick Benjamin Woodruff on 24/07/2021.
//

#include "https_connection.hpp"
#include "http_handler.hpp"
#include "string_utils.hpp"

#include <iostream>
#include <memory>

namespace fbw {

/*
 This gets called when there is data in https_connection::input to handle
 */
void https_connection::handle_session_data() {
    read_app(input);
    try {
        // loop
        if(input.size() > max_bytes_queued) {
            throw http_error("414 URI Too Long");
        }
        if(header.empty()) {
            header = extract(input, "\r\n\r\n");
        }
        //std::cout << header;
        if(!header.empty()) {
            const auto [delimiter, size] = body_size(header);
            assert(delimiter == "" or size == 0);
            std::string body;
            if(delimiter != "") {
                body += extract(input, delimiter);
                throw http_error("418 I'm a teapot");
                // I need to implement this
            } else if(size != 0) {
                body += extract(input, size);
                if(body.size() == 0) {
                    return;
                }
            }
            std::cout << "body size extracted: " << body.size() << std::endl;
            std::cout << "HTTP CLIENT: \n";
            std::cout << header << body;
            std::string response = respond(std::move(header), std::move(body));
            std::cout << "HTTP SERVER: \n";
            std::cout << response;
            write_app(std::move(response));
            header = "";
        }
    } catch(http_error e) {
        std::cout << e.what() << std::endl;
        header = "";
        write_app(std::string(e.what()) + "\r\n");
        tls_notify_close();
    }
}

/*
 TCP layer shouldn't have to worry about TLS or HTTP layer
 but needs to allocate the space for it
 */
std::unique_ptr<connection_base> https_connection::ctor_my() {
    return std::make_unique<https_connection>();
}
 
};// namespace fbw
