/*
 * virus_db.cpp - 加载用户自建的 signatures.json（哈希病毒库）
 * 格式见 data/virus_db/signatures.json。仅做加载、解析与查询，
 * 不包含任何编造的样本数据。
 */
#include "virus_db.h"

#include <fstream>
#include <sstream>

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

} /* anonymous namespace */

std::string VirusDb::load(const std::string& path) {
    std::string text = read_all(path);
    if (text.empty())
        return "cannot read virus db: " + path;

    sg::Json root;
    try {
        root = sg::Json::parse(text);
    } catch (const std::exception& e) {
        return std::string("virus db parse error: ") + e.what();
    }

    if (!root.is_object())
        return "virus db root is not an object";

    by_sha256_.clear();
    by_md5_.clear();
    entries_.clear();

    version_ = root.at("version").as_string();
    updated_ = root.at("updated").as_string();

    const sg::Json& arr = root.at("entries");
    if (arr.is_array()) {
        for (size_t i = 0; i < arr.size(); ++i) {
            const sg::Json& e = arr[i];
            VirusEntry v;
            v.sha256 = to_lower(e.at("sha256").as_string());
            v.md5 = to_lower(e.at("md5").as_string());
            v.name = e.at("name").as_string();
            v.level = (int)e.at("level").as_number();
            v.type = e.at("type").as_string();
            v.family = e.at("family").as_string();
            v.source = e.at("source").as_string();
            if (!v.sha256.empty())
                by_sha256_[v.sha256] = v;
            if (!v.md5.empty())
                by_md5_[v.md5] = v;
            entries_.push_back(v);
        }
    }
    return std::string();
}

bool VirusDb::lookup_sha256(const std::string& sha256, VirusEntry& out) const {
    auto it = by_sha256_.find(to_lower(sha256));
    if (it == by_sha256_.end()) return false;
    out = it->second;
    return true;
}

bool VirusDb::lookup_md5(const std::string& md5, VirusEntry& out) const {
    auto it = by_md5_.find(to_lower(md5));
    if (it == by_md5_.end()) return false;
    out = it->second;
    return true;
}
