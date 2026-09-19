/*
 * realtime_monitor.cpp - 文件系统实时监控
 * Windows：ReadDirectoryChangesW 异步监控目录变化；
 * Linux：inotify 监控。变化文件入队并由引擎扫描，回调 JSON 事件。
 */
#include "realtime_monitor.h"

#include <chrono>
#include <cstring>
#include <filesystem>
#include <queue>

#include "../third_party/json.hpp"
#include "scanner.h"

#ifdef _WIN32
#include <windows.h>
#endif

#ifdef __linux__
#include <sys/inotify.h>
#include <unistd.h>
#include <fcntl.h>
#endif

namespace fs = std::filesystem;

RealtimeMonitor::~RealtimeMonitor() {
    stop();
}

void RealtimeMonitor::set_dirs_json(const std::string& json) {
    dirs_json_ = json;
    try {
        sg::Json arr = sg::Json::parse(json);
        if (arr.is_array()) {
            for (const auto& v : arr.array())
                dirs_.push_back(v.as_string());
        }
    } catch (...) { dirs_.clear(); }
}

void RealtimeMonitor::set_callback(void (*cb)(const char*)) { cb_ = cb; }
void RealtimeMonitor::set_engines(ClamAVEngine* c, YaraEngine* y, VirusDb* v,
                                  BehaviorRules* b, Whitelist* w) {
    clamav_ = c; yara_ = y; vdb_ = v; behavior_ = b; whitelist_ = w;
}

#ifdef _WIN32

void RealtimeMonitor::worker_thread(int idx) {
    if (idx >= (int)dirs_.size() || dirs_[idx].empty()) return;
    const std::string dir = dirs_[idx];
    std::wstring wdir(dir.begin(), dir.end());

    HANDLE hDir = CreateFileW(wdir.c_str(), FILE_LIST_DIRECTORY,
                              FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                              nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
    if (hDir == INVALID_HANDLE_VALUE) return;

    char buffer[65536];
    while (running_.load()) {
        DWORD bytes = 0;
        if (!ReadDirectoryChangesW(hDir, buffer, sizeof buffer, TRUE,
                                   FILE_NOTIFY_CHANGE_FILE_NAME |
                                   FILE_NOTIFY_CHANGE_DIR_NAME |
                                   FILE_NOTIFY_CHANGE_SIZE |
                                   FILE_NOTIFY_CHANGE_LAST_WRITE,
                                   &bytes, nullptr, nullptr)) {
            break;
        }
        DWORD off = 0;
        while (off + sizeof(FILE_NOTIFY_INFORMATION) <= bytes) {
            FILE_NOTIFY_INFORMATION* fni =
                reinterpret_cast<FILE_NOTIFY_INFORMATION*>(buffer + off);
            std::wstring wname(fni->FileName, fni->FileNameLength / 2);
            std::string name(wname.begin(), wname.end());
            std::string full = dir + "\\" + name;
            std::string ev;
            switch (fni->Action) {
                case FILE_ACTION_ADDED: ev = "created"; break;
                case FILE_ACTION_MODIFIED: ev = "modified"; break;
                case FILE_ACTION_REMOVED: ev = "removed"; break;
                case FILE_ACTION_RENAMED_OLD_NAME: ev = "renamed_from"; break;
                case FILE_ACTION_RENAMED_NEW_NAME: ev = "renamed_to"; break;
                default: ev = "changed"; break;
            }
            if (ev == "created" || ev == "modified" || ev == "renamed_to")
                scan_and_emit(full, ev);
            else
                check_mass_write(full);
            if (fni->NextEntryOffset == 0) break;
            off += fni->NextEntryOffset;
        }
    }
    CloseHandle(hDir);
}

#else /* __linux__ */

void RealtimeMonitor::worker_thread(int idx) {
    if (idx >= (int)dirs_.size() || dirs_[idx].empty()) return;
    const std::string dir = dirs_[idx];

    int fd = inotify_init1(IN_NONBLOCK);
    if (fd < 0) return;
    int wd = inotify_add_watch(fd, dir.c_str(),
                               IN_CREATE | IN_MODIFY | IN_MOVED_TO | IN_CLOSE_WRITE);
    if (wd < 0) {
        close(fd);
        return;
    }
    char buffer[65536];
    while (running_.load()) {
        ssize_t len = read(fd, buffer, sizeof buffer);
        if (len <= 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            continue;
        }
        ssize_t off = 0;
        while (off + (ssize_t)sizeof(struct inotify_event) <= len) {
            struct inotify_event* ev = (struct inotify_event*)(buffer + off);
            if (ev->len > 0) {
                std::string name(ev->name);
                std::string full = dir + "/" + name;
                if (ev->mask & (IN_CREATE | IN_CLOSE_WRITE | IN_MOVED_TO))
                    scan_and_emit(full, ev->mask & IN_MOVED_TO ? "moved_to" : "created");
                else if (ev->mask & IN_MODIFY)
                    scan_and_emit(full, "modified");
            }
            off += (ssize_t)sizeof(struct inotify_event) + ev->len;
        }
    }
    inotify_rm_watch(fd, wd);
    close(fd);
}

#endif

void RealtimeMonitor::scan_and_emit(const std::string& path, const std::string& event) {
    std::error_code ec;
    if (!fs::exists(path, ec)) return;
    check_mass_write(path);

    std::string result = Scanner::scan_file(path, clamav_, yara_, vdb_, behavior_, whitelist_);
    sg::Json r;
    try {
        r = sg::Json::parse(result);
    } catch (...) { return; }

    sg::Json ev = sg::Json::make_object();
    ev["type"] = sg::Json::make_string("file");
    ev["event"] = sg::Json::make_string(event);
    ev["path"] = sg::Json::make_string(path);
    ev["status"] = r.at("status");
    ev["threat_name"] = r.at("threat_name");
    ev["engine"] = r.at("engine");
    ev["level"] = r.at("level");
    if (cb_) cb_(ev.dump().c_str());
}

void RealtimeMonitor::check_mass_write(const std::string& path) {
    if (!behavior_) return;
    const BehaviorRule* rule = behavior_->find("MASS_FILE_ENCRYPT");
    if (!rule) return;

    long long now_ms = (long long)std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now().time_since_epoch()).count();
    long long window_ms = rule->threshold_window_sec * 1000;
    std::lock_guard<std::mutex> lk(mass_mutex_);
    recent_writes_.push_back(now_ms);
    while (!recent_writes_.empty() && now_ms - recent_writes_.front() > window_ms)
        recent_writes_.erase(recent_writes_.begin());
    if ((long long)recent_writes_.size() >= rule->threshold_count && cb_) {
        sg::Json ev = sg::Json::make_object();
        ev["type"] = sg::Json::make_string("behavior");
        ev["rule"] = sg::Json::make_string(rule->id);
        ev["name"] = sg::Json::make_string(rule->name);
        ev["level"] = sg::Json::make_number(rule->level);
        ev["path"] = sg::Json::make_string(path);
        ev["count"] = sg::Json::make_number((double)recent_writes_.size());
        ev["action"] = sg::Json::make_string(rule->action);
        cb_(ev.dump().c_str());
        recent_writes_.clear();
    }
}

bool RealtimeMonitor::start() {
    if (running_.load()) return false;
    if (dirs_.empty()) return false;
    running_.store(true);
    for (size_t i = 0; i < dirs_.size(); ++i)
        threads_.emplace_back(&RealtimeMonitor::worker_thread, this, (int)i);
    return true;
}

void RealtimeMonitor::stop() {
    running_.store(false);
    for (auto& t : threads_)
        if (t.joinable()) t.join();
    threads_.clear();
}
