/*
 * dllmain.cpp - SafeGuard DLL 入口与导出函数实现
 * 职责：初始化各引擎、调度扫描、管理全局状态、导出 C 接口。
 */
#include <string>
#include <mutex>
#include <atomic>
#include <vector>
#include <filesystem>
#include <cstring>
#include <algorithm>

#include "../include/safeguard_api.h"
#include "../third_party/json.hpp"

#include "clamav_engine.h"
#include "yara_engine.h"
#include "scanner.h"
#include "quarantine.h"
#include "process_guard.h"
#include "whitelist.h"
#include "realtime_monitor.h"
#include "usb_monitor.h"
#include "registry_monitor.h"
#include "virus_db.h"
#include "behavior_rules.h"

namespace fs = std::filesystem;

/* ---------------- 全局状态 ---------------- */
namespace {

std::recursive_mutex g_mutex;
bool g_inited = false;

ClamAVEngine* g_clamav = nullptr;
YaraEngine* g_yara = nullptr;
VirusDb* g_vdb = nullptr;
BehaviorRules* g_behavior = nullptr;
Whitelist* g_whitelist = nullptr;
Quarantine* g_quarantine = nullptr;

RealtimeMonitor* g_realtime = nullptr;
UsbMonitor* g_usb = nullptr;
RegistryMonitor* g_registry = nullptr;

std::string g_work_dir;   /* 项目根目录，用于定位隔离区、日志 */

/* 跨调用保存返回字符串（简单轮换缓冲，避免 Python 端多次调用互相覆盖） */
constexpr int kStrSlots = 8;
std::vector<std::string> g_str_pool(kStrSlots);
std::atomic<int> g_str_idx{0};

const char* hold_string(const std::string& s) {
    std::lock_guard<std::recursive_mutex> lk(g_mutex);
    int idx = g_str_idx.fetch_add(1) % kStrSlots;
    g_str_pool[idx] = s;
    return g_str_pool[idx].c_str();
}

void free_string(const char* s) {
    (void)s; /* 由池管理，无需真正释放 */
}

std::string project_root() {
    return g_work_dir;
}

} /* anonymous namespace */

/* ---------------- 初始化 ---------------- */

extern "C" int sg_init(const char* clamav_db_dir,
                       const char* yara_rules_path,
                       const char* json_db_path,
                       const char* behavior_rules_path,
                       const char* white_list_path) {
    std::lock_guard<std::recursive_mutex> lk(g_mutex);
    if (g_inited) return 0;

    /* 以可执行文件所在目录向上回溯，定位项目根 */
    try {
        fs::path exe = fs::absolute(fs::path("."));
        g_work_dir = exe.string();
    } catch (...) { g_work_dir = "."; }

    if (clamav_db_dir) {
        g_clamav = new ClamAVEngine(clamav_db_dir);
        std::string err = g_clamav->initialize();
        if (!err.empty()) { delete g_clamav; g_clamav = nullptr; }
    }

    if (yara_rules_path) {
        g_yara = new YaraEngine(yara_rules_path);
        std::string err = g_yara->initialize();
        if (!err.empty()) { delete g_yara; g_yara = nullptr; }
    }

    if (json_db_path) {
        g_vdb = new VirusDb();
        g_vdb->load(json_db_path);
    }

    if (behavior_rules_path) {
        g_behavior = new BehaviorRules();
        g_behavior->load(behavior_rules_path);
    }

    if (white_list_path) {
        g_whitelist = new Whitelist();
        g_whitelist->load(white_list_path);
    }

    g_quarantine = new Quarantine();
    if (!g_quarantine->init(g_work_dir + "/quarantine")) {
        delete g_quarantine;
        g_quarantine = nullptr;
    }

    g_inited = true;
    return 0;
}

extern "C" void sg_shutdown() {
    std::lock_guard<std::recursive_mutex> lk(g_mutex);
    if (!g_inited) return;
    delete g_realtime; g_realtime = nullptr;
    delete g_usb; g_usb = nullptr;
    delete g_registry; g_registry = nullptr;
    delete g_quarantine; g_quarantine = nullptr;
    delete g_behavior; g_behavior = nullptr;
    delete g_whitelist; g_whitelist = nullptr;
    delete g_vdb; g_vdb = nullptr;
    delete g_yara; g_yara = nullptr;
    delete g_clamav; g_clamav = nullptr;
    g_inited = false;
}

extern "C" const char* sg_version() {
    return hold_string("SafeGuard Engine 1.0.0 (libclamav + libyara)");
}

extern "C" const char* sg_clamav_version() {
    if (!g_clamav) return hold_string("clamav:not-initialized");
    return hold_string(g_clamav->version());
}

extern "C" const char* sg_yara_version() {
    if (!g_yara) return hold_string("yara:not-initialized");
    return hold_string(g_yara->version());
}

/* ---------------- 扫描 ---------------- */

extern "C" const char* sg_scan_file(const char* file_path) {
    if (!file_path) return hold_string("{\"status\":\"error\",\"detail\":\"null path\"}");
    std::lock_guard<std::recursive_mutex> lk(g_mutex);
    if (!g_inited)
        return hold_string("{\"status\":\"error\",\"detail\":\"engine not initialized\"}");
    std::string result = Scanner::scan_file(file_path, g_clamav, g_yara, g_vdb,
                                            g_behavior, g_whitelist);
    return hold_string(result);
}

extern "C" const char* sg_scan_dir(const char* dir_path,
                                   void (*progress_cb)(int, int, const char*)) {
    if (!dir_path) return hold_string("{\"status\":\"error\",\"detail\":\"null path\"}");
    std::lock_guard<std::recursive_mutex> lk(g_mutex);
    if (!g_inited)
        return hold_string("{\"status\":\"error\",\"detail\":\"engine not initialized\"}");
    std::string result = Scanner::scan_dir(dir_path, progress_cb,
                                           g_clamav, g_yara, g_vdb,
                                           g_behavior, g_whitelist);
    return hold_string(result);
}

extern "C" int sg_cancel_scan() {
    Scanner::cancel();
    return 0;
}

/* ---------------- 实时监控 ---------------- */

extern "C" int sg_start_realtime_monitor(const char* dirs_json,
                                         void (*event_cb)(const char*)) {
    std::lock_guard<std::recursive_mutex> lk(g_mutex);
    if (!g_inited || g_realtime) return -1;
    g_realtime = new RealtimeMonitor();
    g_realtime->set_dirs_json(dirs_json ? dirs_json : "[]");
    g_realtime->set_callback(event_cb);
    g_realtime->set_engines(g_clamav, g_yara, g_vdb, g_behavior, g_whitelist);
    return g_realtime->start() ? 0 : -1;
}

extern "C" int sg_stop_realtime_monitor() {
    std::lock_guard<std::recursive_mutex> lk(g_mutex);
    if (!g_realtime) return -1;
    g_realtime->stop();
    delete g_realtime;
    g_realtime = nullptr;
    return 0;
}

extern "C" int sg_start_usb_monitor(void (*event_cb)(const char*)) {
    std::lock_guard<std::recursive_mutex> lk(g_mutex);
    if (!g_inited || g_usb) return -1;
    g_usb = new UsbMonitor();
    g_usb->set_callback(event_cb);
    g_usb->set_engines(g_clamav, g_yara, g_vdb, g_behavior, g_whitelist);
    return g_usb->start() ? 0 : -1;
}

extern "C" int sg_stop_usb_monitor() {
    std::lock_guard<std::recursive_mutex> lk(g_mutex);
    if (!g_usb) return -1;
    g_usb->stop();
    delete g_usb;
    g_usb = nullptr;
    return 0;
}

extern "C" int sg_start_registry_monitor(void (*event_cb)(const char*)) {
    std::lock_guard<std::recursive_mutex> lk(g_mutex);
    if (!g_inited || g_registry) return -1;
    g_registry = new RegistryMonitor();
    g_registry->set_callback(event_cb);
    g_registry->set_behavior(g_behavior);
    return g_registry->start() ? 0 : -1;
}

extern "C" int sg_stop_registry_monitor() {
    std::lock_guard<std::recursive_mutex> lk(g_mutex);
    if (!g_registry) return -1;
    g_registry->stop();
    delete g_registry;
    g_registry = nullptr;
    return 0;
}

/* ---------------- 隔离区 ---------------- */

extern "C" int sg_quarantine_add(const char* file_path) {
    if (!file_path || !g_quarantine) return -1;
    return g_quarantine->add(file_path) ? 0 : -1;
}

extern "C" int sg_quarantine_restore(const char* id, const char* restore_path) {
    if (!id || !g_quarantine) return -1;
    return g_quarantine->restore(id, restore_path ? restore_path : "") ? 0 : -1;
}

extern "C" int sg_quarantine_delete(const char* id) {
    if (!id || !g_quarantine) return -1;
    return g_quarantine->remove(id) ? 0 : -1;
}

extern "C" const char* sg_quarantine_list() {
    if (!g_quarantine) return hold_string("[]");
    return hold_string(g_quarantine->list());
}

/* ---------------- 进程与白名单 ---------------- */

extern "C" int sg_block_process(const char* pid_or_path) {
    if (!pid_or_path) return -1;
    return ProcessGuard::block(pid_or_path);
}

extern "C" int sg_allow_once(const char* file_path) {
    if (!file_path || !g_whitelist) return -1;
    g_whitelist->allow_once(file_path);
    return 0;
}

/* ---------------- 热重载 ---------------- */

extern "C" int sg_reload_virus_db(const char* json_db_path,
                                  const char* yara_rules_path) {
    std::lock_guard<std::recursive_mutex> lk(g_mutex);
    int ok = 0;
    if (json_db_path && g_vdb) { g_vdb->load(json_db_path); ok = 1; }
    if (yara_rules_path && g_yara) {
        std::string err = g_yara->reload(yara_rules_path);
        if (err.empty()) ok = 1;
    }
    return ok;
}

extern "C" void sg_free_string(const char* s) {
    free_string(s);
}
