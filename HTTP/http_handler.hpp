//
//  http_handler.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 23/07/2021.
//

#ifndef http_handler_hpp
#define http_handler_hpp

#include <string>

namespace fbw {
/*
 Functions for handing HTTP strings
 */


std::string respond(const std::string& rootdirectory, std::string header, std::string body);
std::string redirect(std::string header, std::string domain);
std::string file_to_http(const std::string& rootdirectory, std::string filename);
void handle_POST(std::string header, std::string body);

} // namespace fbw

#endif /* http_handler_hpp */
