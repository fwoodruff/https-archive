//
//  main.cpp
//  HTTPS Server
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

// HTTP has a lot of state, why not just pass fail on whether a full HTTP framed message can be extracted rather than
// mess around with headers?

// heartbeats are handled safely but wrong

int main() {
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
        fbw::server webserver { };

        while(true) {
            
            webserver.serve_some();
        }
    } catch (const std::system_error& e) {
        std::cerr << "system error: " << e.code() << e.what() << std::endl;
    } catch (const std::runtime_error& e) {
        std::cerr << "runtime error: " << e.what() << std::endl;
    } catch (const std::logic_error& e) {
        std::cerr << "logic error: " << e.what() << std::endl;
    } catch (const std::bad_alloc& e) {
        std::cerr << "std::bad_alloc\n";
    } catch(const std::exception& e) {
        std::cerr << "server shut unexpectedly\n" << e.what() << std::endl;
    } catch(...) {
        std::cerr << "unexpected server close\n" << std::endl;
    }
    std::cerr << "end main()" << std::endl;
}
