/*
 * registry_monitor.cpp - 注册表 Run 启动项监控
 * Windows：RegNotifyChangeKeyValue 监视 HKCU/HKLM 的 Run 键，
 *         变更时按行为规则判定（REG_RUN_PERSIST / DISABLE_DEFENDER）。
 * Linux：注册表概念不存在，返回不支持。
 */
#include "registry_monitor.h"

#include <chrono>
#include <filesystem>

#include "../third_party/json.hpp"

#ifdef _WIN32
#include <windows.h>
#endif

RegistryMonitor::~RegistryMonitor() { stop(); }

void RegistryMonitor::set_callback(void (*cb)(const char*)) { cb_ = cb; }
void RegistryMonitor::set_behavior(BehaviorRules* b) { behavior_ = b; }

void RegistryMonitor::emit_event(const std::string& rule_id,
                                 const std::string& path_value,
                                 const std::string& action) {
    if (!cb_) return;
    sg::Json ev = sg::Json::make_object();
    ev["type"] = sg::Json::make_string("registry");
    ev["rule"] = sg::Json::make_string(rule_id);
    ev["path"] = sg::Json::make_string(path_value);
    ev["action"] = sg::Json::make_string(action);
    cb_(ev.dump().c_str());
}

#ifdef _WIN32

namespace {

/* 判定某条注册表写入是否命中规则 */
bool match_rule(const BehaviorRule* rule, const std::string& key, const std::string& value) {
    if (!rule) return false;
    std::string combined = key + "\\" + value;
    std::string lc;
    for (auto& c : combined) lc += (char)tolower((unsigned char)c);

    if (rule->id == "DISABLE_DEFENDER") {
        return lc.find("defender") != std::string::npos;
    }
    if (rule->id == "REG_RUN_PERSIST") {
        return lc.find("\\run") != std::string::npos;
    }
    /* 通用路径模式 */
    if (!rule->path_pattern.empty()) {
        return BehaviorRules::wildcard_match(rule->path_pattern, combined);
    }
    return false;
}

void watch_key(HKEY root, const wchar_t* subkey, const std::string& key_name,
               const std::atomic<bool>& running, RegistryMonitor* self,
               BehaviorRules* behavior, void (*cb)(const char*)) {
    HKEY hKey = nullptr;
    if (RegOpenKeyExW(root, subkey, 0, KEY_NOTIFY | KEY_READ, &hKey) != ERROR_SUCCESS)
        return;
    while (running.load()) {
        LONG ret = RegNotifyChangeKeyValue(hKey, TRUE,
                                           REG_NOTIFY_CHANGE_LAST_SET |
                                           REG_NOTIFY_CHANGE_NAME,
                                           nullptr, FALSE);
        if (ret != ERROR_SUCCESS) break;
        if (!running.load()) break;
        /* 枚举当前值并判定规则 */
        DWORD idx = 0;
        DWORD name_len = 512;
        DWORD data_len = 4096;
        wchar_t name[512];
        wchar_t data[4096];
        while (RegEnumValueW(hKey, idx++, name, &name_len, nullptr,
                             nullptr, (LPBYTE)data, &data_len) == ERROR_SUCCESS) {
            name_len = 512;
            data_len = 4096;
            std::wstring wname(name), wdata(data);
            std::string sname(wname.begin(), wname.end());
            std::string sdata(wdata.begin(), wdata.end());
            if (behavior) {
                const BehaviorRule* r = behavior->find("REG_RUN_PERSIST");
                if (r && match_rule(r, key_name, sname + "=" + sdata)) {
                    self->emit_event(r->id, key_name + "\\" + sname, r->action);
                }
                r = behavior->find("DISABLE_DEFENDER");
                if (r && match_rule(r, key_name, sname + "=" + sdata)) {
                    self->emit_event(r->id, key_name + "\\" + sname, r->action);
                }
            }
        }
    }
    RegCloseKey(hKey);
}

} /* anonymous namespace */

void RegistryMonitor::worker_thread() {
    std::thread t1(watch_key, HKEY_CURRENT_USER,
                   L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                   "HKCU\\...\\Run", std::cref(running_), this, behavior_, cb_);
    std::thread t2(watch_key, HKEY_LOCAL_MACHINE,
                   L"Software\\Microsoft\\Windows\\CurrentVersion\\Run",
                   "HKLM\\...\\Run", std::cref(running_), this, behavior_, cb_);
    t1.join();
    t2.join();
}

#else

void RegistryMonitor::worker_thread() {
    /* 非 Windows 平台不支持注册表监控，等待退出信号 */
    while (running_.load())
        std::this_thread::sleep_for(std::chrono::milliseconds(500));
}

#endif

bool RegistryMonitor::start() {
    if (running_.load()) return false;
    running_.store(true);
    thread_ = std::thread(&RegistryMonitor::worker_thread, this);
    return true;
}

void RegistryMonitor::stop() {
    running_.store(false);
    if (thread_.joinable()) thread_.join();
}
