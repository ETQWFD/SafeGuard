/*
 * behavior_rules.h - 行为规则（behavior_rules.json）加载与判定
 */
#ifndef SG_BEHAVIOR_RULES_H
#define SG_BEHAVIOR_RULES_H

#include <string>
#include <vector>

#include "../third_party/json.hpp"

struct BehaviorRule {
    std::string id;
    std::string name;
    int level = 0;
    std::string trigger;      /* registry_write / usb_insert / file_write / file_copy */
    std::string path_pattern;
    std::string file_pattern;
    std::string action;       /* alert / block */
    long long threshold_count = 0;
    long long threshold_window_sec = 0;
};

class BehaviorRules {
public:
    std::string load(const std::string& path);
    const std::vector<BehaviorRule>& rules() const { return rules_; }

    /* 按 id 查找规则 */
    const BehaviorRule* find(const std::string& id) const;

    /* 简单通配匹配：支持 * 与 ? */
    static bool wildcard_match(const std::string& pattern, const std::string& text);

private:
    std::vector<BehaviorRule> rules_;
};

#endif /* SG_BEHAVIOR_RULES_H */
