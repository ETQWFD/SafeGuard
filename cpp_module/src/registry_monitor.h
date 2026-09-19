/*
 * registry_monitor.h - 注册表启动项监控
 */
#ifndef SG_REGISTRY_MONITOR_H
#define SG_REGISTRY_MONITOR_H

#include <string>
#include <thread>
#include <atomic>
#include <mutex>

#include "behavior_rules.h"

class RegistryMonitor {
public:
    RegistryMonitor() = default;
    ~RegistryMonitor();

    void set_callback(void (*cb)(const char*));
    void set_behavior(BehaviorRules* b);

    bool start();
    void stop();

private:
    void worker_thread();
    void emit_event(const std::string& rule_id, const std::string& path_value,
                    const std::string& action);

    void (*cb_)(const char*) = nullptr;
    BehaviorRules* behavior_ = nullptr;
    std::thread thread_;
    std::atomic<bool> running_{false};
    std::mutex mutex_;
};

#endif /* SG_REGISTRY_MONITOR_H */
