/*
 * behavior_rules.cpp - 行为规则加载与通配匹配
 * 规则由用户维护，AI 提供完整模板（见 data/virus_db/behavior_rules.json）。
 */
#include "behavior_rules.h"

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

std::string BehaviorRules::load(const std::string& path) {
    std::string text = read_all(path);
    if (text.empty())
        return "cannot read behavior rules: " + path;

    sg::Json root;
    try {
        root = sg::Json::parse(text);
    } catch (const std::exception& e) {
        return std::string("behavior rules parse error: ") + e.what();
    }
    rules_.clear();
    const sg::Json& arr = root.at("rules");
    if (arr.is_array()) {
        for (size_t i = 0; i < arr.size(); ++i) {
            const sg::Json& r = arr[i];
            BehaviorRule rule;
            rule.id = r.at("id").as_string();
            rule.name = r.at("name").as_string();
            rule.level = (int)r.at("level").as_number();
            rule.trigger = r.at("trigger").as_string();
            rule.path_pattern = r.at("path_pattern").as_string();
            rule.file_pattern = r.at("file_pattern").as_string();
            rule.action = r.at("action").as_string();
            const sg::Json& th = r.at("threshold");
            if (th.is_object()) {
                rule.threshold_count = (long long)th.at("count").as_number();
                rule.threshold_window_sec = (long long)th.at("window_sec").as_number();
            }
            rules_.push_back(rule);
        }
    }
    return std::string();
}

const BehaviorRule* BehaviorRules::find(const std::string& id) const {
    for (const auto& r : rules_)
        if (r.id == id) return &r;
    return nullptr;
}

bool BehaviorRules::wildcard_match(const std::string& pattern, const std::string& text) {
    /* 迭代式通配匹配（* 和 ?），大小写不敏感 */
    size_t p = 0, t = 0, star = std::string::npos, mark = 0;
    std::string lp = to_lower(pattern), lt = to_lower(text);
    while (t < lt.size()) {
        if (p < lp.size() && (lp[p] == '?' || lp[p] == lt[t])) {
            ++p; ++t;
        } else if (p < lp.size() && lp[p] == '*') {
            star = p++;
            mark = t;
        } else if (star != std::string::npos) {
            p = star + 1;
            t = ++mark;
        } else {
            return false;
        }
    }
    while (p < lp.size() && lp[p] == '*') ++p;
    return p == lp.size();
}
