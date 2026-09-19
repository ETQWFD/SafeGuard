/*
 * yara_engine.cpp - libyara 真实规则引擎集成
 * 编译 .yar 规则文件并扫描文件，需先安装 yara 开发库。
 */
#include "yara_engine.h"

#include <yara.h>
#include <cstdio>
#include <cstring>
#include <chrono>
#include <string>

namespace {

struct MatchCtx {
    std::vector<std::string>* matches;
};

int rule_callback(YR_SCAN_CONTEXT* ctx, int message, void* data, void* user_data) {
    (void)ctx;
    if (message != CALLBACK_MSG_RULE_MATCHING)
        return CALLBACK_CONTINUE;
    YR_RULE* rule = static_cast<YR_RULE*>(data);
    if (rule && user_data) {
        MatchCtx* mctx = static_cast<MatchCtx*>(user_data);
        mctx->matches->push_back(rule->identifier);
    }
    return CALLBACK_CONTINUE;
}

} /* anonymous namespace */

YaraEngine::YaraEngine(const std::string& rules_path)
    : rules_path_(rules_path), rules_(nullptr), rule_count_(0) {
    version_ = YR_VERSION;
}

YaraEngine::~YaraEngine() {
    shutdown();
}

std::string YaraEngine::initialize() {
    if (yr_initialize() != ERROR_SUCCESS)
        return "yr_initialize failed";
    return reload(rules_path_);
}

std::string YaraEngine::reload(const std::string& rules_path) {
    if (rules_path.empty())
        return "empty yara rules path";

    YR_COMPILER* compiler = nullptr;
    if (yr_compiler_create(&compiler) != ERROR_SUCCESS)
        return "yr_compiler_create failed";

    FILE* f = std::fopen(rules_path.c_str(), "rb");
    if (!f) {
        yr_compiler_destroy(compiler);
        return "cannot open yara rules file: " + rules_path;
    }
    const char* namespace_name = "sg";
    int errors = yr_compiler_add_file(compiler, f, namespace_name, nullptr);
    std::fclose(f);

    if (errors > 0) {
        yr_compiler_destroy(compiler);
        return "yara compile errors: " + std::to_string(errors);
    }

    YR_RULES* new_rules = nullptr;
    if (yr_compiler_get_rules(compiler, &new_rules) != ERROR_SUCCESS) {
        yr_compiler_destroy(compiler);
        return "yr_compiler_get_rules failed";
    }
    int new_count = 0;
    {
        YR_RULE* rule_it = nullptr;
        yr_rules_foreach(new_rules, rule_it) {
            (void)rule_it;
            new_count++;
        }
    }
    yr_compiler_destroy(compiler);

    std::lock_guard<std::mutex> lk(scan_mutex_);
    if (rules_) yr_rules_destroy(rules_);
    rules_ = new_rules;
    rule_count_ = new_count;
    rules_path_ = rules_path;
    return std::string();
}

void YaraEngine::shutdown() {
    std::lock_guard<std::mutex> lk(scan_mutex_);
    if (rules_) {
        yr_rules_destroy(rules_);
        rules_ = nullptr;
    }
    yr_finalize();
}

std::string YaraEngine::version() const {
    return version_;
}

int YaraEngine::scan_file(const std::string& path, std::vector<std::string>& matches,
                          std::string& error, long long& scan_ms) {
    std::lock_guard<std::mutex> lk(scan_mutex_);
    if (!rules_) {
        error = "yara rules not loaded";
        return -1;
    }

    auto t0 = std::chrono::steady_clock::now();
    MatchCtx ctx{&matches};
    int ret = yr_rules_scan_file(rules_, path.c_str(),
                                 SCAN_FLAGS_FAST_MODE, rule_callback, &ctx, 0);
    auto t1 = std::chrono::steady_clock::now();
    scan_ms = (long long)std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    if (ret != ERROR_SUCCESS) {
        error = "yr_rules_scan_file error code " + std::to_string(ret);
        return -1;
    }
    return 0;
}
