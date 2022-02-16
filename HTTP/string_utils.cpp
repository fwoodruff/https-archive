//
//  http_header.cpp
//  piserver
//
//  Created by Frederick Benjamin Woodruff on 15/07/2021.
//

#include "string_utils.hpp"
#include "keccak.hpp"

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
    file_assert(header.find("\r\n\r\n") != std::string::npos, "header.find(\r\n\r\n) != std::string::npos");
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
            } catch(const std::invalid_argument& e) {
                throw http_error("400 Bad Request");
            }
        } else if (content.size() > multipart.size() and content.substr(0, multipart.size()) == multipart) {
            const auto n = content.find("\r\n");
            file_assert(n != std::string::npos, "string utils 138: n != npos");
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
    file_assert(header.find("\r\n\r\n") != std::string::npos, "bad get_argument header input" );
    const static std::string endline = "\r\n";
    //header.append(endline);
    const static std::string colon = ": ";
    file_assert(field.max_size() > field.size() + endline.size()+ colon.size(), "bad field size");
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
    file_assert(line_length != std::string::npos, "header did not contain an endline");

    size_t distance = 0;
    while(true) {
        const auto n = header.find(delimiter,distance); // 8

        if (n == std::string::npos or n >= line_length) {
            file_assert (distance <= line_length, "get method distance <= line_length"); // fired
            const std::string ntoken = header.substr(distance, line_length-distance);
            if(ntoken != "") {
                out.push_back(std::move(ntoken));
            }
            break;
        }
        const std::string token = header.substr(distance, n-distance); // GET/test
        if(token != "") {
            out.push_back(std::move(token));
        }
        distance = n + delimiter.size(); // 9
    }
    return out;
}


void shuffle(std::array<uint8_t, 32>& state) {
    for(int i = 0; i < 3; i++) {
        for(int j = 0; j < 32; j++) {
            state[j] += (state[(j+10)%32] << 4) * (state[(j+7)%32] >> 1);
            state[j] ^= state[j] >> 3;
        }
    }
}

std::string make_eTag(const std::string& file_contents) {
    std::array<uint8_t, 32> state {0};
    for(unsigned i = 0; i < file_contents.size(); i ++) {
        state[i % 24] ^= file_contents[i];
        if(i % 23 == 0) {
            shuffle(state);
        }
    }
    shuffle(state);
    state[2] = 0x22;
    
    std::ostringstream ss;
    for(size_t i = 0; i < 8; ++i) {
        ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(state[i]);
    }
    return ss.str();
}

std::vector<std::string> operating_systems {
    "(5G Vaccine Mast Tower)",
    "(Not an OS, just some guy waving a magnet)",
    "(The Cloud)",
    "(Wandows 3000)",
    "(MS-DOS 4.0)",
    "(Windows Vista)",
    "(Atari DOS)",
    "(iPadOS)",
    "(RISC OS)",
    "(XTS-400)",
    "(Apple Pascal)",
    "(Acorn MOS) (BBC Micro)",
    "(Acorn MOS) (Acorn Electron)",
    "(iOS)",
    "(Harmony OS)",
    "(Intel) (ISIS)",
    "(Vulcan O/S)",
    "(INTEGRITY-178B)",
    "(MSP-EX)",
    "(PDP-10) (TENEX)",
    "(PDP-10) (TOPS-20)",
    "(ENIAC)",
    "(TempleOS)",
    "(Collapse OS)",
    "(AROS) (Commadore)",
    "(Red Star OS 3.0)",
    "(Visopsys)"
    "(HeartOS) (DDC-I)"
};

std::string make_server_name() {
    uint8_t random_bytes[2];
    randomgen.randgen(random_bytes, 2);
    std::string server_name = "FredPi/0.1 " ;
    if(random_bytes[0] > 22) {
        server_name+= "(Unix) (Raspbian/Linux)";
    } else {
        server_name += operating_systems[random_bytes[1] % operating_systems.size()];
    }
    return server_name;
}


} // namespace fbw
