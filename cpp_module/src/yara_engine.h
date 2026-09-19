/*
 * yara_engine.h - libyara 规则引擎封装
 */
#ifndef SG_YARA_ENGINE_H
#define SG_YARA_ENGINE_H

#include <string>
#include <mutex>
#include <vector>

typedef struct YR_RULES YR_RULES;

class YaraEngine {
public:
    explicit YaraEngine(const std::string& rules_path);
    ~YaraEngine();

    std::string initialize();
    std::string reload(const std::string& rules_path);
    void shutdown();
    std::string version() const;
    int rule_count() const { return rule_count_; }

    /*
     * 扫描文件，匹配的规则名写入 matches。
     * 返回 0 成功（无论是否匹配）、-1 错误（error 说明）。
     */
    int scan_file(const std::string& path, std::vector<std::string>& matches,
                  std::string& error, long long& scan_ms);

private:
    std::string rules_path_;
    std::string version_;
    YR_RULES* rules_;
    int rule_count_;
    std::mutex scan_mutex_;
};

#endif /* SG_YARA_ENGINE_H */
