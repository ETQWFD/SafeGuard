/* 交叉编译桩：隔离区用文件移动 + JSON 元数据，不依赖 OpenSSL。
   Windows 正式版由 build.bat 链接 OpenSSL 启用 AES-256。 */
#include "quarantine.h"
#include "../third_party/json.hpp"
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <sstream>

namespace fs = std::filesystem;

Quarantine::Quarantine() : dir_("./quarantine") {}
Quarantine::~Quarantine() { shutdown(); }

bool Quarantine::init(const std::string& dir) {
    dir_ = dir;
    std::error_code ec;
    fs::create_directories(dir_, ec);
    return !ec;
}
void Quarantine::shutdown() {}

std::string Quarantine::add(const std::string& path) {
    std::error_code ec;
    if (!fs::exists(path, ec)) return "";
    std::string id = "q_" + std::to_string((unsigned)std::time(nullptr)) + "_" +
                     std::to_string(reinterpret_cast<uintptr_t>(path.c_str()));
    fs::copy_file(path, dir_ + "/" + id + ".bin", fs::copy_options::overwrite_existing, ec);
    if (ec) return "";
    sg::Json meta = sg::Json::make_object();
    meta["id"] = sg::Json::make_string(id);
    meta["original_path"] = sg::Json::make_string(path);
    meta["timestamp"] = sg::Json::make_string(std::to_string(std::time(nullptr)));
    std::ofstream out(dir_ + "/" + id + ".json");
    out << meta.dump();
    return id;
}

bool Quarantine::restore(const std::string& id, const std::string& to_path) {
    std::error_code ec;
    fs::copy_file(dir_ + "/" + id + ".bin", to_path, fs::copy_options::overwrite_existing, ec);
    return !ec;
}

bool Quarantine::remove(const std::string& id) {
    std::error_code ec;
    fs::remove(dir_ + "/" + id + ".bin", ec);
    fs::remove(dir_ + "/" + id + ".json", ec);
    return true;
}

std::string Quarantine::list() {
    sg::Json arr = sg::Json::make_array();
    std::error_code ec;
    for (auto& e : fs::directory_iterator(dir_, ec)) {
        if (e.path().extension() == ".json") {
            std::ifstream in(e.path());
            std::stringstream ss; ss << in.rdbuf();
            try { arr.push_back(sg::Json::parse(ss.str())); } catch (...) {}
        }
    }
    return arr.dump();
}
