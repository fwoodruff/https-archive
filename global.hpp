//
//  global.hpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 07/12/2021.
//

#ifndef global_hpp
#define global_hpp


#include <cassert>
#include <string>
#include <array>
#include <iostream>
#include <fstream>


extern std::fstream logger;

namespace fbw {


extern const std::string key_file;
extern const std::string certificate_file;
extern const std::string MIME_folder;
extern const std::string rootdir;
extern const std::string domain_name;

extern const ssize_t MAX_SOCKETS;
extern const int timeoutms;
extern const ssize_t BUFFER_SIZE;







using ustring = std::basic_string<uint8_t>;
[[nodiscard]] inline uint64_t safe_asval(const ustring& s, size_t idx, size_t bytes) {
    uint64_t len = 0;
    for(size_t i = idx; i < idx + bytes; i ++) {
        len <<=8;
        len |= s.at(i);
    }
    return len;
}

inline void write_int(uint64_t x, uint8_t* const s, short n) noexcept {
    assert(static_cast<size_t>(n) >= sizeof(uint64_t) or x < (1ull << (n*8)));
    assert(static_cast<size_t>(n) <= sizeof(uint64_t)); // avoids ub
    for(short i = n-1; i >= 0; i--) {
        s[i] = static_cast<uint8_t>(x) & 0xffU;
        x>>=8;
    }
}


[[nodiscard]] inline ustring to_unsigned(std::string s) {
    ustring out;
    out.append(s.cbegin(), s.cend());
    return out;
}

[[nodiscard]] inline std::string to_signed(ustring s) {
    std::string out;
    out.append(s.cbegin(), s.cend());
    return out;
}

} // namespace fbw


inline void file_assert(bool assertion, const std::string_view& message) {
    if(!assertion) {
        logger << message << std::endl;
        logger.close();
        std::terminate();
    }
}


template<typename CALLABLE>
class raii_guard {
    CALLABLE dtor;
public:
    raii_guard(CALLABLE callable) : dtor(callable) {}
    ~raii_guard() { dtor(); }
};


#endif /* global_hpp */
