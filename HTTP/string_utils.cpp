//
//  http_header.cpp
//  piserver
//
//  Created by Frederick Benjamin Woodruff on 15/07/2021.
//

#include "string_utils.hpp"

#include <sys/stat.h>

#include <string>
#include <ctime>
#include <iomanip>
#include <unordered_set>
#include <sstream>
#include <cassert>
#include <iostream>

/*
 To do:
 create a map from http error numbers to code names
 include the file creation date in the output
 make file_exists more portable
 */

namespace fbw {

/*
 convert current time for string
 used in response header
 */
std::string timestring(time_t t) {
    char buf[48];
    const std::tm tm = *std::gmtime(&t);
    std::strftime(buf, sizeof buf, "%a, %d %b %Y %H:%M:%S %Z", &tm);
    const std::string out(buf);
    return out;
}

/*
 
time_t get_file_date(FILE* file) {
    if(file == nullptr) {
        throw http_error("500 Internal Server Error");
    }
    const int fd = fileno(file);
    // check fd and file
    
    struct stat statbuf;
    const int x =  fstat(fd, &statbuf);
    if(x == -1) {
        throw http_error("500 Internal Server Error");
    }
    return statbuf.st_mtime;

}*/

/*
 not currently used and not portable
 safe to delete
 */
bool file_exists (const std::string& name) {
  struct stat buffer;
  return (stat (name.c_str(), &buffer) == 0);
}

/*
 hexdump
 */
std::string hexStr(const uint8_t* const data, int len) {
    std::ostringstream ss;
    for(int i = 0; i < len; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
    }
    return ss.str();
}




/*
 helps parse HTTP streams
 */
std::string extract(std::string& bytes, std::string delimiter) {
    if(delimiter == "") return "";
    const size_t n = bytes.find(delimiter);
    if (n == std::string::npos) {
        return "";
    }
    std::string ret = bytes.substr(0, n+delimiter.size()+1);
    bytes = bytes.substr(n+delimiter.size());
    return ret;
}


std::string extract(std::string& bytes, size_t nbytes) {
    if(nbytes == 0) return "";
    const auto n = bytes.size();
    if(n < nbytes) {
        return std::string();
    }
    const std::string ret = bytes.substr(0, n);
    bytes = bytes.substr(n);
    return ret;
}

/*
 List of HTTP request types
 Used to distinguish between malformed requests and unsupported requests
 */
const static std::unordered_set<std::string> verbs {"GET", "HEAD", "POST", "PUT",
                                                "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};

/*
 uses the header to find the length of the HTTP body
 the return tpe is a length or a delimiter
 */
std::pair<std::string, size_t> body_size(const std::string& header) {
    assert(header.find("\r\n\r\n") != std::string::npos);
    const auto method = get_method(header);
    if (method.empty() or (verbs.find(method[0]) == verbs.end())) {
        throw http_error("400 Bad Request");
    }
    if(method[0] == "GET") {
        return {std::string(), 0};
    } else if (method[0] == "POST") {
        const std::string content = fbw::get_argument(header, "Content-Type");
        if (content == "") {
            throw http_error("400 Bad Request");
        }
        const std::string multipart = "multipart/form-data;boundary=\"";
        
        if(content == "application/x-www-form-urlencoded") {
            const std::string arg = fbw::get_argument(header, "Content-Length");
            if(arg == "") {
                throw http_error("411 Length Required");
            }
            try {
                return {std::string(), std::stoi(arg) };
            } catch(std::invalid_argument e) {
                throw http_error("400 Bad Request");
            }
        } else if (content.size() > multipart.size() and content.substr(0, multipart.size()) == multipart) {
            const auto n = content.find("\r\n");
            assert(n != std::string::npos);
            std::string delimiter = content.substr(multipart.size(), n);
            if (delimiter=="") {
                throw http_error("400 Bad Request");
            }
            delimiter = delimiter.insert(0,"--");
            delimiter = delimiter.append("--");
            return {delimiter, 0};
        } else {
            throw http_error("501 Not Implemented");
        }
    } else {
        throw http_error("405 Method Not Allowed");
    }
    assert(false);
}



/*
 Used for finding the Content-Type, Content-Length etc.
 */
std::string get_argument(const std::string& header, std::string field) {
    assert(header.find("\r\n\r\n") != std::string::npos);
    const static std::string endline = "\r\n";
    //header.append(endline);
    const static std::string colon = ": ";
    assert(field.max_size() > field.size() + endline.size()+ colon.size());
    field.insert(0,endline);
    field.append(colon);
    const auto n = header.find(field);
    if(n == std::string::npos) {
        return "";
    }
    const auto st = n + field.size();
    const auto q = header.find(endline,st);
    if(q == std::string::npos) {
        return "";
    }
    return header.substr(st, q-st);
}

/*
 Tokenises a request header e.g. {'GET', '/<filename>', "HTTP/1.1" }
 */
std::vector<std::string> get_method(const std::string& header) {
    const std::string delimiter = " ";
    const std::string endline = "\r\n";
    std::vector<std::string> out;
    const auto line_length = header.find(endline);
    assert(line_length != std::string::npos);
    
    size_t distance = 0;
    while(true) {
        const auto n = header.find(delimiter,distance);

        if (n == std::string::npos or n >= line_length) {
            assert (distance < line_length);
            const std::string ntoken = header.substr(distance, line_length-distance);
            if(ntoken != "") {
                out.push_back(std::move(ntoken));
            }
            break;
        }
        const std::string token = header.substr(distance, n-distance);
        if(token != "") {
            out.push_back(std::move(token));
        }
        distance = n + delimiter.size();
    }
    return out;
}

} // namespace fbw
