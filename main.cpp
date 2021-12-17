//
//  main.cpp
//
//  Created by Frederick Benjamin Woodruff on 08/07/2021.
//


#include "server.hpp"
#include "https_connection.hpp"


#include <new>
#include <iostream>
#include <cstdio>
#include <cassert>
#include <cstdint>
#include <string>
#include <array>

int main() {
    {
        std::ifstream t(fbw::key_file);
        if(t.fail()) {
           std::cout << "no key" << std::endl;
           std::terminate();
        }
        std::ifstream u(fbw::certificate_file);
        if(u.fail()) {
            std::cout << "no certificate" << std::endl;
            std::terminate();
        }
        std::ifstream v(fbw::rootdir);
        if(v.fail()) {
            std::cout << "no webpages" << std::endl;
            std::terminate();
        }
        std::ifstream w(fbw::MIME_folder);
        if(w.fail()) {
            std::cout << "no MIME" << std::endl;
            std::terminate();
        }
    }

    try {
        
        fbw::server webserver { fbw::https_connection::ctor_my,"https" };
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
}
