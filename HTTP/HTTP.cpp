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
 Unencrypted raw bytes get buffered in here.
 Responses are concatenated for each fully framed HTTP request, otherwise an empty value is returned.
 */
status_message HTTP::handle(ustring uinput) noexcept {
    input.append(to_signed(std::move(uinput)));
    status_message output { .m_status = status::read_write };
    try {
        for(;;) {
            if(input.size() > max_bytes_queued) {
                throw http_error("414 URI Too Long");
            }
            if(header.empty()) {
                header = extract(input, "\r\n\r\n");
            }
            if(header.empty()) {
                break;
            }
            
            const auto [delimiter, size] = body_size(header);
            assert(delimiter == "" or size == 0);
            std::string body;
            if(delimiter != "") {
                body += extract(input, delimiter);
                throw http_error("418 I'm a teapot");
            }
            if(size != 0) {
                body += extract(input, size);
                if(body.size() == 0) {
                    return output;
                }
            }
            
            std::string response;
            
            if(m_redirect) {
                response = redirect(std::move(header), domain_name);
            } else {
                response = respond(m_folder, std::move(header), std::move(body));
            }
            header.clear();

            output.m_response += to_unsigned(std::move(response));
        }
    } catch(const http_error& e) {
        header.clear();
        
        auto error_message = std::string(e.what());
        
        std::ostringstream oss;
        oss << "HTTP/1.1 " << error_message << "\r\n"
        << "Connection: close\r\n"
        << "Content-Type: text/html; charset=UTF-8\r\n"
        << "Content-Length: " << error_message.size() << "\r\n"
        << "Server: FredPi/0.1 (Unix) (Raspbian/Linux)\r\n"
        << "\r\n"
        << error_message;
        output.m_response += to_unsigned(oss.str());
        output.m_status = status::closing;
    } catch(const std::logic_error& e) {
        output.m_status = status::closing;
    } catch(...) {
        assert(false);
    }
    return output;
}
 
};// namespace fbw
