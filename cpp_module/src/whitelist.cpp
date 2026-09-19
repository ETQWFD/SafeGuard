/*
 * whitelist.cpp - 白名单实现
 * 原则：绝不误杀——系统目录默认放行；带有效数字签名的文件放行；
 * 用户可在设置页维护自定义白名单（写入 white_list.json）。
 */
#include "whitelist.h"

#include <fstream>
#include <sstream>
#include <algorithm>
#include <filesystem>
#include <cstring>

#ifdef _WIN32
#include <windows.h>
#include <wintrust.h>
#include <softpub.h>
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "crypt32.lib")
#endif

#include "../third_party/json.hpp"

namespace {

std::string read_all(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::string();
    std::ostringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

std::string to_lower(const std::string& s) {
    std::string out = s;
    for (auto& c : out)
        if (c >= 'A' && c <= 'Z') c = (char)(c - 'A' + 'a');
    return out;
}

/* 系统目录前缀（不区分大小写路径前缀） */
const char* kSystemPrefixes[] = {
    "c:\\windows", "c:\\program files", "c:\\program files (x86)",
    "c:\\programdata", "c:\\$recycle.bin", "c:\\system volume information",
    "\\windows", "/usr", "/bin", "/sbin", "/etc", "/lib", "/lib64",
    "/opt", "/boot", "/proc", "/sys", "/dev", "/run", "/snap",
    "/System/Library", "/Library", "/usr/local"
};

} /* anonymous namespace */

std::string Whitelist::load(const std::string& path) {
    db_path_ = path;
    std::string text = read_all(path);
    if (text.empty())
        return "cannot read whitelist: " + path;
    sg::Json root;
    try {
        root = sg::Json::parse(text);
    } catch (const std::exception& e) {
        return std::string("whitelist parse error: ") + e.what();
    }
    custom_.clear();
    const sg::Json& arr = root.at("paths");
    if (arr.is_array()) {
        for (size_t i = 0; i < arr.size(); ++i)
            custom_.push_back(arr[i].as_string());
    }
    return std::string();
}

bool Whitelist::has_system_prefix(const std::string& path) const {
    std::string lp = to_lower(path);
    for (const char* p : kSystemPrefixes) {
        if (lp.compare(0, strlen(p), p) == 0)
            return true;
    }
    /* 自定义前缀（目录形式） */
    for (const auto& c : custom_) {
        std::string lc = to_lower(c);
        if (lp.compare(0, lc.size(), lc) == 0)
            return true;
    }
    return false;
}

bool Whitelist::is_signed_binary(const std::string& path) const {
#ifdef _WIN32
    /* 使用 WinVerifyTrust 校验 Authenticode 签名 */
    std::wstring wpath(path.begin(), path.end());
    WINTRUST_FILE_INFO file_info;
    std::memset(&file_info, 0, sizeof(file_info));
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = wpath.c_str();

    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    WINTRUST_DATA data;
    std::memset(&data, 0, sizeof(data));
    data.cbStruct = sizeof(data);
    data.dwUnionChoice = WTD_CHOICE_FILE;
    data.pFile = &file_info;
    data.dwUIChoice = WTD_UI_NONE;
    data.fdwRevocationChecks = WTD_REVOKE_NONE;
    data.dwStateAction = WTD_STATEACTION_VERIFY;
    data.dwProvFlags = WTD_SAFER_FLAG | WTD_CACHE_ONLY_URL_RETRIEVAL;

    LONG ret = WinVerifyTrust(nullptr, &action, &data);
    data.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &data);
    return ret == ERROR_SUCCESS;
#else
    (void)path;
    return false;
#endif
}

bool Whitelist::is_whitelisted(const std::string& file_path) {
    std::lock_guard<std::mutex> lk(mutex_);
    if (has_system_prefix(file_path))
        return true;
    for (const auto& t : temp_allowed_)
        if (t == file_path) return true;
    /* 白名单自定义条目中的精确文件 */
    for (const auto& c : custom_) {
        if (to_lower(c) == to_lower(file_path))
            return true;
    }
    /* 带有效数字签名的可执行文件优先放行 */
    std::string ext = to_lower(std::filesystem::path(file_path).extension().string());
    if (ext == ".exe" || ext == ".dll" || ext == ".sys") {
        if (is_signed_binary(file_path))
            return true;
    }
    return false;
}

void Whitelist::allow_once(const std::string& file_path) {
    std::lock_guard<std::mutex> lk(mutex_);
    temp_allowed_.push_back(file_path);
    /* 持久化到 white_list.json */
    try {
        sg::Json root = sg::Json::make_object();
        sg::Json arr = sg::Json::make_array();
        for (const auto& c : custom_) arr.push_back(sg::Json::make_string(c));
        for (const auto& t : temp_allowed_) arr.push_back(sg::Json::make_string(t));
        root["paths"] = arr;
        std::ofstream out(db_path_, std::ios::trunc);
        if (out) out << root.dump();
    } catch (...) { /* 忽略持久化失败 */ }
}
