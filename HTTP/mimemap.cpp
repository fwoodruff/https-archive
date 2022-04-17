//
//  mimemap.cpp
//  HTTPS Server
//
//  Created by Frederick Benjamin Woodruff on 20/07/2021.
//
#include "global.hpp"
#include "mimemap.hpp"
#include "string_utils.hpp"


#include <dirent.h>

#include <unordered_map>
#include <string>
#include <fstream>
#include <sstream>
#include <vector>

namespace fbw {


decltype(MIMES("")) MIMEmap;
bool init = false;

/*
 Populates a map from the MIME type file
 */
std::unordered_map<std::string,std::string> MIME_csv_to_map(std::string filename) {
    std::ifstream file (filename);
    std::string line;
    std::unordered_map<std::string,std::string> MIME_types;
    while(std::getline(file, line)) {
        std::istringstream s(line);
        std::string field;
        std::vector<std::string> fields;
        while (std::getline(s, field,',')) {
            fields.push_back(field);
        }
        MIME_types.insert({fields[0],fields[1]});
    }
    return MIME_types;
}

/*
 Aggregates a number of MIME files into one map
 */
std::unordered_map<std::string,std::string> MIMES(std::string directory_name) {
    std::unordered_map<std::string,std::string> map;
    DIR *dir;
    struct dirent *ent;

    if ((dir = opendir (directory_name.c_str())) != nullptr) {
        std::unordered_map<std::string,std::string> mimes;
        while ((ent = ::readdir (dir)) != nullptr) {
            const auto filen = std::string(ent->d_name);
            if (filen=="." or filen=="..") {
                continue;
            }
            std::string filenn = directory_name + "/" + filen;
            auto map = MIME_csv_to_map(filenn);
            mimes.insert(map.cbegin(),map.cend());
        }
        closedir (dir);
        return mimes;
    } else {
        throw std::runtime_error("MIME csv folder not found\n");
    }
}



/*
 The file in the get request header, e.g. /footballscores.html has an extension .html
 Note this is not always trivial to extract for all MIME types since some extensions have multiple '.' tokens
 and the body of the request could also have one
 */
std::string extension_from_path(std::string path) {
    std::string filename;
    const std::string slash = "/";
    const auto last = path.find_last_of(slash);
    if(last!=std::string::npos) {
        filename = path.substr(last + slash.size());
    } else {
        filename = path;
    }
    const std::string delimiter = ".";
    if(filename.size()<delimiter.size()) return "";
    if(filename.substr(filename.size()-delimiter.size()) == delimiter) {return "";}
    if(filename.find(delimiter)==std::string::npos) {return ""; }
    
    
    for(long i = filename.size()-delimiter.size(); i >= 0; --i) {
        if(filename.substr(i,delimiter.size()) == delimiter) {
            auto ext = filename.substr(i+delimiter.size());
            if(MIMEmap.find(ext) != MIMEmap.end()) {
                return ext;
            }
        }
    }
    auto str = filename.substr(filename.find_last_of(delimiter) + delimiter.size());
    return str;
}

/*
 Returns the MIME type for a given extension
 e.g. html -> text/html
 This is used in the header of the GET response
 */
std::string get_MIME(std::string extension) {
    static std::once_flag init_MIME {};
    std::call_once(init_MIME, [&](){MIMEmap = MIMES(MIME_folder);});
    try {
        return MIMEmap.at(extension);
    } catch(const std::logic_error& e) {
        throw http_error("415 Unsupported Media Type");
    }
}

} // namespace fbw
