//
//  global.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 13/12/2021.
//

#include "global.hpp"

#include <string>
#include <fstream>

#if __linux__
//const std::string fbw::key_file = "/etc/letsencrypt/live/freddiewoodruff.co.uk/fullchain.pem";
//const std::string fbw::certificate_file = "/etc/letsencrypt/live/freddiewoodruff.co.uk/privkey.pem";

const std::string fbw::key_file = "ecc_key.pem";
const std::string fbw::certificate_file = "ecc_cert.pem";
const std::string fbw::MIME_folder = "MIME";
const std::string fbw::rootdir ("webpages");
const ssize_t fbw::MAX_SOCKETS = 5000;
const int fbw::timeoutms = 5000;
const ssize_t fbw::BUFFER_SIZE = 2000;

std::fstream logger("log.txt", std::ios_base::out | std::ios_base::trunc);

#else


const std::string fbw::key_file = "/Users/freddiewoodruff/Documents/Programming/https_server/ecc_key.pem";
const std::string fbw::certificate_file = "/Users/freddiewoodruff/Documents/Programming/https_server/https_server/TLS/ecc_cert.pem";
const std::string fbw::MIME_folder = "/Users/freddiewoodruff/Documents/Programming/https_server/https_server/HTTP/MIME";
const std::string fbw::rootdir ("/Users/freddiewoodruff/Documents/Programming/https_server/https_server/webpages");

std::fstream logger("/Users/freddiewoodruff/Documents/Programming/https_server/https_server/log.txt",
                    std::ios_base::out | std::ios_base::trunc);


const ssize_t fbw::MAX_SOCKETS = 5000;
const int fbw::timeoutms = 5000;
const ssize_t fbw::BUFFER_SIZE = 2000;
#endif






