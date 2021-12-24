//
//  main.cpp
//
//  Created by Frederick Benjamin Woodruff on 08/07/2021.
//




#include "server.hpp"
#include "global.hpp"
#include "TLS.hpp"

#include <new>
#include <iostream>
#include <cstdio>
#include <cassert>
#include <cstdint>
#include <string>
#include <array>
#include <fstream>
#include <thread>


class redirect : public fbw::receiver {
public:
    fbw::status_message handle(fbw::ustring in) noexcept override {
        auto x = std::string().append(in.begin(), in.end());
        std::cout << x << std::endl;
        
        std::string s = "HTTP/1.1 301 Moved Permanently\r\nLocation:\r\nhttps://localhost/index.html\r\n\r\n";
        return {fbw::ustring().append(s.begin(), s.end()),fbw::status::closing};
    }
};


// look at I/O for requesting a PDF to understand why it is occasionally so slow



void loop() {
    if(logger.fail()) {
        std::cout << "logger problem" << std::endl;
        std::terminate();
    }
    file_assert(true, "file_assert failed...");
    
    std::time_t start_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());

    logger << "Start server at: " << std::ctime(&start_time);
    
    fbw::TLS().test_handshake();
    
    uint64_t loop_counter = 0;
    
    
    logger << "start main()" << std::endl;
    try {
            {
                std::ifstream t(fbw::key_file);
                if(t.fail()) {
                    throw std::runtime_error("no key");
                }
                std::ifstream u(fbw::certificate_file);
                if(u.fail()) {
                    throw std::runtime_error("no certificate");
                }
                std::ifstream v(fbw::rootdir);
                if(v.fail()) {
                    throw std::runtime_error("no root directory");
                }
                std::ifstream w(fbw::MIME_folder);
                if(w.fail()) {
                    throw std::runtime_error("no MIME");
                }
            }
        
        fbw::server webserver {
            "https", [] {
                auto x = std::make_unique<fbw::TLS>();
                x->next = std::make_unique<fbw::HTTP>(fbw::rootdir);
                return x;
            }
        };
        
        
        
        
            
        
        while(true) {
            logger << "loop count: " << loop_counter << std::endl;
            loop_counter++;
            webserver.serve_some();
        }
    } catch (const std::system_error& e) {
        logger << "system error: " << e.code() << e.what() << std::endl;
    } catch (const std::runtime_error& e) {
        logger << "runtime error: " << e.what() << std::endl;
    } catch (const std::logic_error& e) {
        logger << "logic error: " << e.what() << std::endl;
    } catch (const std::bad_alloc& e) {
        logger << "std::bad_alloc\n";
    } catch(const std::exception& e) {
        logger << "server shut unexpectedly\n" << e.what() << std::endl;
    } catch(...) {
        logger << "unexpected server close\n" << std::endl;
    }
    logger << "end main()" << std::endl;
}

void red() {
    try {
        fbw::server redirect_server {
             "http", [] {
                 return std::make_unique<redirect>();
             }
        };
        while(true) {
            redirect_server.serve_some();
        }
    } catch(...) {
        logger << "redirect failed()" << std::endl;
    }
}

int main() {
    std::thread th1([]() {
        loop();
    });
    
    std::thread th2([]() {
        red();
    });
    th2.join();
    
     
    th1.join();
    
}
