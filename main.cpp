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


#include "chacha20poly1305.hpp"


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
