//
//  http_handler.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 23/07/2021.
//

#include "keccak.hpp"
#include "secure_hash.hpp"
#include "http_handler.hpp"
#include "mimemap.hpp"
#include "string_utils.hpp"
#include "global.hpp"

#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <regex>

namespace fbw {


/*
 Creates an HTTP response from an HTTP request
 */
std::string respond(const std::string& rootdirectory, std::string header, std::string body) {
    const auto method = get_method(header);
    if(method.size() < 3) {
        throw http_error("400 Bad Request");
    }
    
    const std::string& filename = method[1];
    if(method[2] != "HTTP/1.0" and method[2] != "HTTP/1.1") {
        throw http_error("505 HTTP Version Not Supported");
    }
    
    if(method[0] == "GET") {
        const std::string out = file_to_http(rootdirectory, filename);
        return out;
    }
    if(method[0] == "POST") {
        handle_POST(std::move(header), std::move(body));
        return file_to_http(rootdir, filename);
    }
    throw http_error("405 Method Not Allowed\r\n");
}

/*
 Here we are just sanitising the inputs and putting them in a file
 */
void handle_POST(std::string header, std::string body) {
    (void)header;
    std::ofstream fout(rootdir+"/final.html", std::ios_base::app);
    body = std::regex_replace(body, std::regex("username="), "username: ");
    body = std::regex_replace(body, std::regex("&password="), ", password: ");
    body = std::regex_replace(body, std::regex("&confirm="), ", confirmed: ");
    body = std::regex_replace(body, std::regex("<"), "&lt;");
    body = std::regex_replace(body, std::regex(">"), "&gt;");
    body.append("</p>");
    body.insert(0,"<p>");
    fout << body << std::endl;
}


/*
 GET requests need to return files with a header
 */
std::string file_to_http(const std::string& rootdir, std::string filename) {
    constexpr time_t day = 24*60*60;
    
    std::transform(filename.begin(), filename.end(), filename.begin(),
        [](unsigned char c){ return std::tolower(c); });
    
    if( filename == "/") {
        filename = "/index.html";
    }
    
    if(filename.find(".") == std::string::npos) {
        filename.append(".html");
    }
    
    std::string MIME;
    if(filename == "/favicon.ico") {
        MIME = "image/webp";
    } else {
        auto extension = extension_from_path(filename);
        MIME = get_MIME(std::move(extension));
    }
    
    
    std::ifstream t(rootdir+filename);
    
    if(t.fail()){
        throw http_error("404 Not Found");
    }
    std::ostringstream buffer;
    buffer << t.rdbuf();
    std::string file_contents = buffer.str();

    auto time = std::time(0);
    if((std::time_t)(-1) == time) {
        throw http_error("500 Internal Server Error");
    }

    std::ostringstream oss;
    oss << "HTTP/1.1 200 OK\r\n"
        << "Date: " << timestring(time) << "\r\n"
        << "Expires: " << timestring(time + day) << "\r\n"
        << "Content-Type: " << MIME << (MIME.substr(0,4)=="text" ? "; charset=UTF-8" : "") << "\r\n"
        << "Content-Length: " << file_contents.size() << "\r\n"
        << "Connection: Keep-Alive\r\n"
        << "Keep-Alive: timeout=5, max=1000\r\n"
        << "Server: " << make_server_name() << "\r\n"
        << "ETag: " << make_eTag(file_contents) << "\r\n"
        << "\r\n"
        << file_contents;
    
    std::string var = oss.str();
    return var;
}


std::string redirect(std::string header, std::string domain) {
    const auto method = get_method(header);
    if(method.size() < 3) {
        throw http_error("400 Bad Request");
    }
    
    std::string filename = method[1];
    
    if( filename == "/") {
        filename = "/index.html";
    }
    
    std::string MIME;
    if(filename == "/favicon.ico") {
        MIME = "image/webp";
    } else {
        auto extension = extension_from_path(filename);
        MIME = get_MIME(std::move(extension));
    }
    
    std::string body = "HTTP/1.1 301 Moved Permanently";
    
    std::ostringstream oss;
    oss << "HTTP/1.1 301 Moved Permanently\r\n"
        << "Location: https://" << domain << filename << "\r\n"
        << "Content-Type: " << MIME << (MIME.substr(0,4)=="text" ? "; charset=UTF-8" : "") << "\r\n"
        << "Content-Length: " << body.size() << "\r\n"
        << "Server: " << make_server_name() << "\r\n"
        << "\r\n"
        << body;
    
    std::string var = oss.str();
    return var;
}


} // fbw
