//
//  http_header.hpp
//  piserver
//
//  Created by Frederick Benjamin Woodruff on 15/07/2021.
//

#ifndef string_utils_hpp
#define string_utils_hpp

#include "global.hpp"

#include <string>
#include <vector>
#include <stdexcept>
#include <cstdio>
#include <utility>


namespace fbw {

/*
 throw HTTP error status codes
 */
class http_error : public std::runtime_error {
    using std::runtime_error::runtime_error;
};

/*
 A pretty timestamp for response headers
 */
[[nodiscard]] std::string timestring(time_t t);
/*
 Gets the date the file was created
 */
time_t get_file_date(std::FILE* file);

bool file_exists (const std::string& name);

/*
 returns n bytes FIFO from an HTTP stream, and removes those bytes from the stream
 Note that this returns an empty string if there are fewer than n bytes in the stream
 O(N) in the current length of the stream
 */
std::string extract(std::string& bytes, size_t nbytes);

/*
 returns bytes FIFO up to a delimiter from an HTTP stream, and removes those bytes from the stream
 Note that this returns an empty string if the delimiter is not present
 O(N) in the current length of the stream
 */
std::string extract(std::string& bytes, std::string delimiter);

/*
 Headers a series of fields
 Content-Type, Content-Length etc.
 What value does this field take?
 */
[[nodiscard]] std::string get_argument(const std::string& header, std::string field);
/*
 This tokenises a request header e.g. {'GET', '/<filename>', "HTTP/1.1" }
 */
[[nodiscard]] std::vector<std::string> get_method(const std::string& header);
/*
 returns the length of the body or its closing delimiter depending on the encoding
 */
[[nodiscard]] std::pair<std::string, size_t> body_size(const std::string& header);

/*
 A file checksum to send in the response header
 Not cryptographically secure
 */
[[nodiscard]] std::string make_eTag(const std::string& file_contents);

std::string make_server_name();

} // namespace fbw
#endif /* string_utils_hpp */
