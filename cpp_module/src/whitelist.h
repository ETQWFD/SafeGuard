/*
 * whitelist.h - 白名单：系统目录、用户自定义路径、签名文件放行
 */
#ifndef SG_WHITELIST_H
#define SG_WHITELIST_H

#include <string>
#include <vector>
#include <mutex>

class Whitelist {
public:
    Whitelist() = default;

    std::string load(const std::string& path);

    /* 命中白名单返回 true（含系统目录前缀与自定义条目） */
    bool is_whitelisted(const std::string& file_path);

    /* 临时放行一次（内存） */
    void allow_once(const std::string& file_path);

    const std::vector<std::string>& custom_entries() const { return custom_; }

private:
    bool has_system_prefix(const std::string& path) const;
    bool is_signed_binary(const std::string& path) const;

    std::vector<std::string> custom_;       /* 用户自定义路径/前缀 */
    std::vector<std::string> temp_allowed_; /* 本次会话放行 */
    std::string db_path_;
    std::mutex mutex_;
};

#endif /* SG_WHITELIST_H */
