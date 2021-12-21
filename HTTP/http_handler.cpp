//
//  http_handler.cpp
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
std::string respond(std::string header, std::string body) {
    const auto method = get_method(header);
    if(method.size()<2) {
        throw http_error("400 Bad Request");
    }
    
    const std::string& filename = method[1];
    if(method.size() > 2 and (method[2] != "HTTP/1.0" and method[2] != "HTTP/1.1")) {
        throw http_error("505 HTTP Version Not Supported");
    }
    
    if(method[0] == "GET") {
        const std::string out = file_to_http(rootdir, filename);
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
    
    if( filename == "/") {
        filename = "/index.html";
    }
    std::string MIME;
    if(filename == "/favicon.ico") {
        MIME = "image/webp";
    } else {
        MIME = get_MIME(extension_from_path(filename));
    }
    std::ifstream t(rootdir+filename);
    if(t.fail()){
        throw http_error("404 Not Found");
    }
    std::ostringstream buffer;
    buffer << t.rdbuf();
    std::string file_contents = buffer.str();

    /*
     // I don't trust the reinterpret cast
    sha256 eTag_hasher;
    eTag_hasher.update(reinterpret_cast<uint8_t*>(&*file_contents.data()), file_contents.size());
    auto eTag = eTag_hasher.hash();
     */
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
        // << "Last-Modified: " << timestring(get_file_date(file.get())) << "\r\n"
        << "Server: FredPi/0.1 (Unix) (Raspbian/Linux)\r\n"
        // << "ETag: " << bytes_to_hex_string(eTag.data(), eTag.size()) << "\r\n"
        << "\r\n"
        << file_contents;
    
    std::string var = oss.str();
    return var;
}

} // fbw
