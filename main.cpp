//
//  main.cpp
//
//  Created by Frederick Benjamin Woodruff on 08/07/2021.
//




#include "server.hpp"
#include "global.hpp"

#include <new>
#include <iostream>
#include <cstdio>
#include <cassert>
#include <cstdint>
#include <string>
#include <array>
#include <fstream>

#include "galois_counter.hpp"


// look at I/O for requesting a PDF to understand why it is occasionally so slow

int main() {
    file_assert(true, "main failed...");
    //fbw::aes::test();
    //exit(1);
    
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
        
        fbw::server webserver { "https" };
        while(true) {
            webserver.serve_some();
        }
    } catch (std::system_error e) {
        std::cerr << "system error: " << e.code() << e.what() << std::endl;
    } catch (std::runtime_error e) {
        std::cerr << "runtime error: " << e.what() << std::endl;
    } catch (std::logic_error e) {
        std::cerr << "logic error: " << e.what() << std::endl;
    } catch (const std::bad_alloc& e) {
        std::cerr << "std::bad_alloc\n";
    } catch(std::exception e) {
        std::cerr << "server shut unexpectedly\n" << e.what() << std::endl;
    } catch(...) {
        std::cerr << "unexpected server close\n" << std::endl;
    }
    logger << "end main()" << std::endl;
}
