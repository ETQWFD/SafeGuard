/*
 * usb_monitor.h - U 盘插拔检测与自动扫描
 */
#ifndef SG_USB_MONITOR_H
#define SG_USB_MONITOR_H

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

class UsbMonitor {
public:
    UsbMonitor() = default;
    ~UsbMonitor();

    void set_callback(void (*cb)(const char*));
    void set_engines(ClamAVEngine* c, YaraEngine* y, VirusDb* v,
                     BehaviorRules* b, Whitelist* w);

    bool start();
    void stop();

private:
    void worker_thread();
    void emit(const std::string& event, const std::string& drive,
              const std::string& extra);
    void scan_drive(const std::string& drive);

    void (*cb_)(const char*) = nullptr;
    ClamAVEngine* clamav_ = nullptr;
    YaraEngine* yara_ = nullptr;
    VirusDb* vdb_ = nullptr;
    BehaviorRules* behavior_ = nullptr;
    Whitelist* whitelist_ = nullptr;

    std::thread thread_;
    std::atomic<bool> running_{false};
    std::mutex mutex_;
    std::vector<std::string> known_drives_;
};

#endif /* SG_USB_MONITOR_H */
