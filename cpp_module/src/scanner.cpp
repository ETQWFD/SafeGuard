/*
 * scanner.cpp - 扫描调度核心
 * 单文件流程：白名单 → 哈希库 → ClamAV → YARA → PE/行为启发 → clean。
 * 目录扫描：收集文件列表，线程池并发扫描，进度回调 + 可取消。
 */
#include "scanner.h"

#include <atomic>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "../third_party/json.hpp"

#include "clamav_engine.h"
#include "yara_engine.h"
#include "virus_db.h"
#include "behavior_rules.h"
#include "whitelist.h"
#include "hasher.h"
#include "pe_analyzer.h"

namespace fs = std::filesystem;

namespace {

std::atomic<bool> g_cancel{false};

struct ScanResult {
    std::string path;
    std::string status;       /* clean|suspicious|infected|error */
    std::string threat_name;
    std::string sha256;
    std::string md5;
    int level = 0;
    std::string engine;
    std::string detail;
    long long scan_ms = 0;
};

ScanResult build_error(const std::string& path, const std::string& detail) {
    ScanResult r;
    r.path = path;
    r.status = "error";
    r.detail = detail;
    return r;
}

/* 行为规则文件级检查：autorun.inf 等 */
ScanResult check_behavior_file(const std::string& path, BehaviorRules* behavior) {
    ScanResult r;
    std::string fname = fs::path(path).filename().string();
    std::string lname;
    for (auto& c : fname) lname += (char)tolower((unsigned char)c);

    if (lname == "autorun.inf" && behavior) {
        const BehaviorRule* rule = behavior->find("USB_AUTORUN");
        if (rule) {
            r.status = "suspicious";
            r.threat_name = rule->name;
            r.level = rule->level;
            r.engine = "behavior";
            r.detail = "matched rule: " + rule->id;
        }
    }
    return r;
}

/* 单文件完整扫描（供目录扫描线程调用） */
ScanResult scan_one(const std::string& path,
                    ClamAVEngine* clamav, YaraEngine* yara,
                    VirusDb* vdb, BehaviorRules* behavior,
                    Whitelist* whitelist) {
    ScanResult r;
    r.path = path;
    std::error_code ec;
    if (!fs::exists(path, ec) || fs::is_directory(path, ec))
        return build_error(path, "not exists or is directory");

    auto t0 = std::chrono::steady_clock::now();

    /* 1. 白名单 */
    if (whitelist && whitelist->is_whitelisted(path)) {
        r.status = "clean";
        r.engine = "whitelist";
        r.detail = "whitelisted path";
        r.sha256 = Hasher::file_sha256(path);
        r.md5 = Hasher::file_md5(path);
        r.scan_ms = (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t0).count();
        return r;
    }

    /* 2. 真实哈希 */
    r.sha256 = Hasher::file_sha256(path);
    r.md5 = Hasher::file_md5(path);

    /* 3. 哈希病毒库 */
    if (vdb) {
        VirusEntry entry;
        bool hit = vdb->lookup_sha256(r.sha256, entry) || vdb->lookup_md5(r.md5, entry);
        if (hit) {
            r.status = "infected";
            r.threat_name = entry.name;
            r.level = entry.level;
            r.engine = "hash";
            r.detail = "hash db match (source: " + entry.source + ")";
            r.scan_ms = (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
                            std::chrono::steady_clock::now() - t0).count();
            return r;
        }
    }

    /* 4. ClamAV 引擎 */
    if (clamav) {
        std::string threat, err;
        long long ms = 0;
        int ret = clamav->scan_file(path, threat, err, ms);
        if (ret > 0) {
            r.status = "infected";
            r.threat_name = threat;
            r.level = 5;
            r.engine = "clamav";
            r.detail = "libclamav detection";
            r.scan_ms = ms;
            return r;
        }
        if (ret < 0) {
            r.scan_ms = ms;
            /* 引擎错误不终止，继续走后续引擎 */
        }
    }

    /* 5. YARA 规则 */
    if (yara) {
        std::vector<std::string> matches;
        std::string err;
        long long ms = 0;
        int ret = yara->scan_file(path, matches, err, ms);
        if (ret == 0 && !matches.empty()) {
            r.status = "suspicious";
            r.threat_name = matches[0];
            r.level = 4;
            r.engine = "yara";
            std::string detail = "matched rule";
            for (const auto& m : matches) detail += " " + m;
            r.detail = detail;
            r.scan_ms = ms;
            return r;
        }
    }

    /* 6. PE / 启发式 */
    if (fs::path(path).extension() == ".exe" || fs::path(path).extension() == ".dll") {
        std::string pe_json = PeAnalyzer::analyze(path);
        try {
            sg::Json pe = sg::Json::parse(pe_json);
            if (pe.at("is_pe").as_bool() && pe.at("packed").as_bool()) {
                r.status = "suspicious";
                r.threat_name = "Packed." + pe.at("packer").as_string();
                r.level = 3;
                r.engine = "heuristic";
                r.detail = "packed binary: " + pe.at("packer").as_string() +
                           " (entropy " + pe.at("entropy").as_string() + ")";
                r.scan_ms = (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
                                std::chrono::steady_clock::now() - t0).count();
                return r;
            }
        } catch (...) { /* 解析失败忽略 */ }
    }

    /* 7. 行为规则文件检查 */
    ScanResult b = check_behavior_file(path, behavior);
    if (!b.status.empty()) {
        b.path = path;
        b.sha256 = r.sha256;
        b.md5 = r.md5;
        b.scan_ms = (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t0).count();
        return b;
    }

    r.status = "clean";
    r.engine = "multi";
    r.detail = "no threat found";
    r.scan_ms = (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
                    std::chrono::steady_clock::now() - t0).count();
    return r;
}

std::string result_json(const ScanResult& r) {
    sg::Json o = sg::Json::make_object();
    o["status"] = sg::Json::make_string(r.status);
    o["threat_name"] = sg::Json::make_string(r.threat_name);
    o["sha256"] = sg::Json::make_string(r.sha256);
    o["md5"] = sg::Json::make_string(r.md5);
    o["level"] = sg::Json::make_number(r.level);
    o["engine"] = sg::Json::make_string(r.engine);
    o["detail"] = sg::Json::make_string(r.detail);
    o["scan_time_ms"] = sg::Json::make_number(r.scan_ms);
    o["path"] = sg::Json::make_string(r.path);
    return o.dump();
}

} /* anonymous namespace */

namespace Scanner {

std::string scan_file(const std::string& path,
                      ClamAVEngine* clamav, YaraEngine* yara,
                      VirusDb* vdb, BehaviorRules* behavior,
                      Whitelist* whitelist) {
    if (path.empty())
        return "{\"status\":\"error\",\"detail\":\"empty path\"}";
    ScanResult r = scan_one(path, clamav, yara, vdb, behavior, whitelist);
    return result_json(r);
}

void cancel() {
    g_cancel.store(true);
}

std::string scan_dir(const std::string& dir,
                     void (*progress_cb)(int, int, const char*),
                     ClamAVEngine* clamav, YaraEngine* yara,
                     VirusDb* vdb, BehaviorRules* behavior,
                     Whitelist* whitelist) {
    g_cancel.store(false);

    /* 收集文件列表 */
    std::vector<std::string> files;
    std::error_code ec;
    if (!fs::exists(dir, ec)) {
        sg::Json o = sg::Json::make_object();
        o["status"] = sg::Json::make_string("error");
        o["detail"] = sg::Json::make_string("directory not found");
        return o.dump();
    }
    try {
        fs::recursive_directory_iterator it(dir, fs::directory_options::skip_permission_denied, ec);
        fs::recursive_directory_iterator end;
        for (; it != end && !g_cancel.load(); it.increment(ec)) {
            if (fs::is_regular_file(it->path(), ec)) {
                files.push_back(it->path().string());
            }
        }
    } catch (...) { /* 部分目录不可读则跳过 */ }

    const size_t total = files.size();
    std::atomic<size_t> done{0};
    std::vector<ScanResult> results;
    std::mutex results_mutex;

    unsigned int nthreads = std::max(2u, std::min(8u, std::thread::hardware_concurrency()));

    auto worker = [&]() {
        while (!g_cancel.load()) {
            size_t idx = done.fetch_add(1);
            if (idx >= files.size()) break;
            ScanResult r = scan_one(files[idx], clamav, yara, vdb, behavior, whitelist);
            {
                std::lock_guard<std::mutex> lk(results_mutex);
                results.push_back(r);
            }
            if (progress_cb) {
                int cur = (int)(idx + 1);
                progress_cb(cur, (int)total, files[idx].c_str());
            }
        }
    };

    std::vector<std::thread> pool;
    for (unsigned int i = 0; i < nthreads; ++i)
        pool.emplace_back(worker);
    for (auto& t : pool) t.join();

    /* 汇总 */
    sg::Json summary = sg::Json::make_object();
    sg::Json infected = sg::Json::make_array();
    sg::Json suspicious = sg::Json::make_array();
    sg::Json errors = sg::Json::make_array();
    long long clean = 0;
    long long total_ms = 0;
    for (const auto& r : results) {
        if (r.status == "infected") {
            sg::Json item = sg::Json::make_object();
            item["path"] = sg::Json::make_string(r.path);
            item["threat_name"] = sg::Json::make_string(r.threat_name);
            item["engine"] = sg::Json::make_string(r.engine);
            infected.push_back(item);
        } else if (r.status == "suspicious") {
            sg::Json item = sg::Json::make_object();
            item["path"] = sg::Json::make_string(r.path);
            item["threat_name"] = sg::Json::make_string(r.threat_name);
            item["engine"] = sg::Json::make_string(r.engine);
            suspicious.push_back(item);
        } else if (r.status == "clean") {
            ++clean;
        } else {
            sg::Json item = sg::Json::make_object();
            item["path"] = sg::Json::make_string(r.path);
            item["detail"] = sg::Json::make_string(r.detail);
            errors.push_back(item);
        }
        total_ms += r.scan_ms;
    }
    summary["status"] = sg::Json::make_string(g_cancel.load() ? "canceled" : "done");
    summary["total"] = sg::Json::make_number((double)total);
    summary["scanned"] = sg::Json::make_number((double)results.size());
    summary["clean"] = sg::Json::make_number((double)clean);
    summary["infected"] = infected;
    summary["suspicious"] = suspicious;
    summary["errors"] = errors;
    summary["total_ms"] = sg::Json::make_number((double)total_ms);
    return summary.dump();
}

} /* namespace Scanner */
