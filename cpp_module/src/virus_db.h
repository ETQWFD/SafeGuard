/*
 * virus_db.h - 哈希病毒库（signatures.json）加载与查询
 */
#ifndef SG_VIRUS_DB_H
#define SG_VIRUS_DB_H

#include <string>
#include <unordered_map>

#include "../third_party/json.hpp"

struct VirusEntry {
    std::string sha256;
    std::string md5;
    std::string name;
    int level = 0;
    std::string type;
    std::string family;
    std::string source;
};

class VirusDb {
public:
    VirusDb() = default;

    /* 加载 signatures.json；失败返回错误描述 */
    std::string load(const std::string& path);

    /* 按 sha256 查询；未命中返回 false */
    bool lookup_sha256(const std::string& sha256, VirusEntry& out) const;

    /* 按 md5 查询 */
    bool lookup_md5(const std::string& md5, VirusEntry& out) const;

    int total() const { return (int)entries_.size(); }
    std::string version() const { return version_; }

private:
    std::string version_;
    std::string updated_;
    std::unordered_map<std::string, VirusEntry> by_sha256_;
    std::unordered_map<std::string, VirusEntry> by_md5_;
    std::vector<VirusEntry> entries_;
};

#endif /* SG_VIRUS_DB_H */
