/*
 * realtime_monitor.h - 文件系统实时监控
 */
#ifndef SG_REALTIME_MONITOR_H
#define SG_REALTIME_MONITOR_H

#include <string>
#include <thread>
#include <atomic>
#include <mutex>
#include <vector>

#include "clamav_engine.h"
#include "yara_engine.h"
#include "virus_db.h"
#include "behavior_rules.h"
#include "whitelist.h"

class RealtimeMonitor {
public:
    RealtimeMonitor() = default;
    ~RealtimeMonitor();

    void set_dirs_json(const std::string& json);
    void set_callback(void (*cb)(const char*));
    void set_engines(ClamAVEngine* c, YaraEngine* y, VirusDb* v,
                     BehaviorRules* b, Whitelist* w);

    bool start();
    void stop();

private:
    void worker_thread(int idx);
    void scan_and_emit(const std::string& path, const std::string& event);
    void check_mass_write(const std::string& path);

    std::vector<std::string> dirs_;
    std::string dirs_json_;
    void (*cb_)(const char*) = nullptr;
    ClamAVEngine* clamav_ = nullptr;
    YaraEngine* yara_ = nullptr;
    VirusDb* vdb_ = nullptr;
    BehaviorRules* behavior_ = nullptr;
    Whitelist* whitelist_ = nullptr;

    std::vector<std::thread> threads_;
    std::atomic<bool> running_{false};
    std::mutex mutex_;

    /* 批量写入检测窗口 */
    std::mutex mass_mutex_;
    struct WriteStamp { long long ts; };
    std::vector<long long> recent_writes_;
};

#endif /* SG_REALTIME_MONITOR_H */
