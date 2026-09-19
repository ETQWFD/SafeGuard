/*
 * usb_monitor.cpp - U 盘插拔监控
 * Windows：RegisterDeviceNotification + WM_DEVICECHANGE 消息循环
 * （独立隐藏窗口线程），识别卷设备到达/移除并映射盘符。
 * Linux：轮询 /proc/partitions + /media、/run/media 挂载目录增量。
 */
#include "usb_monitor.h"

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <set>

#include "../third_party/json.hpp"
#include "scanner.h"
#include "behavior_rules.h"

#ifdef _WIN32
#include <windows.h>
#include <dbt.h>
#include <initguid.h>
DEFINE_GUID(GUID_SG_VOLUME, 0x53f5630d, 0xb6bf, 0x11d0, 0x94, 0xf2, 0x00, 0xa0, 0xc9, 0x1e, 0xfb, 0x8b);
#endif

namespace fs = std::filesystem;

namespace {

#ifdef _WIN32
/* 由 DBT_DEVTYP_VOLUME 的 unitmask 计算盘符 */
std::string unitmask_to_letters(DWORD mask) {
    std::string letters;
    for (int i = 0; i < 26; ++i) {
        if (mask & (1u << i))
            letters += (char)('A' + i);
    }
    return letters;
}
#endif

} /* anonymous namespace */

UsbMonitor::~UsbMonitor() { stop(); }

void UsbMonitor::set_callback(void (*cb)(const char*)) { cb_ = cb; }
void UsbMonitor::set_engines(ClamAVEngine* c, YaraEngine* y, VirusDb* v,
                             BehaviorRules* b, Whitelist* w) {
    clamav_ = c; yara_ = y; vdb_ = v; behavior_ = b; whitelist_ = w;
}

void UsbMonitor::emit(const std::string& event, const std::string& drive,
                      const std::string& extra) {
    if (!cb_) return;
    sg::Json ev = sg::Json::make_object();
    ev["type"] = sg::Json::make_string("usb");
    ev["event"] = sg::Json::make_string(event);
    ev["drive"] = sg::Json::make_string(drive);
    ev["extra"] = sg::Json::make_string(extra);
    cb_(ev.dump().c_str());
}

void UsbMonitor::scan_drive(const std::string& drive) {
    std::error_code ec;
    if (!fs::exists(drive, ec)) return;

    /* autorun.inf 行为规则检查 */
    std::string autorun = drive + (drive.back() == '/' || drive.back() == '\\'
                                       ? "autorun.inf" : "/autorun.inf");
    if (fs::exists(autorun, ec) && behavior_) {
        const BehaviorRule* rule = behavior_->find("USB_AUTORUN");
        if (rule) {
            sg::Json ev = sg::Json::make_object();
            ev["type"] = sg::Json::make_string("usb");
            ev["event"] = sg::Json::make_string("autorun_found");
            ev["drive"] = sg::Json::make_string(drive);
            ev["path"] = sg::Json::make_string(autorun);
            ev["threat_name"] = sg::Json::make_string(rule->name);
            ev["level"] = sg::Json::make_number(rule->level);
            ev["action"] = sg::Json::make_string(rule->action);
            if (cb_) cb_(ev.dump().c_str());
        }
    }

    /* 自动扫描 U 盘根目录（深度 2，避免卡顿） */
    try {
        fs::recursive_directory_iterator it(drive,
            fs::directory_options::skip_permission_denied, ec);
        fs::recursive_directory_iterator end;
        int depth = 0;
        for (; it != end; it.increment(ec)) {
            std::error_code lvl;
            int d = it.depth();
            if (d > 2) {
                it.disable_recursion_pending();
                continue;
            }
            if (fs::is_regular_file(it->path(), lvl)) {
                std::string result = Scanner::scan_file(it->path().string(),
                                                        clamav_, yara_, vdb_,
                                                        behavior_, whitelist_);
                sg::Json r;
                try { r = sg::Json::parse(result); } catch (...) { continue; }
                std::string st = r.at("status").as_string();
                if (st == "infected" || st == "suspicious") {
                    sg::Json ev = sg::Json::make_object();
                    ev["type"] = sg::Json::make_string("usb");
                    ev["event"] = sg::Json::make_string("threat");
                    ev["drive"] = sg::Json::make_string(drive);
                    ev["path"] = sg::Json::make_string(it->path().string());
                    ev["status"] = sg::Json::make_string(st);
                    ev["threat_name"] = r.at("threat_name");
                    ev["engine"] = r.at("engine");
                    ev["level"] = r.at("level");
                    if (cb_) cb_(ev.dump().c_str());
                }
            }
            (void)depth;
        }
    } catch (...) { /* 忽略不可读目录 */ }
}

#ifdef _WIN32

void UsbMonitor::worker_thread() {
    /* 隐藏窗口 + 消息循环，接收 WM_DEVICECHANGE */
    const wchar_t kClassName[] = L"SafeGuardUsbWnd";
    WNDCLASSW wc;
    std::memset(&wc, 0, sizeof(wc));
    wc.lpfnWndProc = [](HWND hwnd, UINT msg, WPARAM wp, LPARAM lp) -> LRESULT {
        UsbMonitor* self = (UsbMonitor*)GetWindowLongPtrW(hwnd, GWLP_USERDATA);
        if (msg == WM_DEVICECHANGE && self) {
            if (wp == DBT_DEVICEARRIVAL || wp == DBT_DEVICEREMOVECOMPLETE) {
                DEV_BROADCAST_HDR* hdr = (DEV_BROADCAST_HDR*)lp;
                if (hdr && hdr->dbch_devicetype == DBT_DEVTYP_VOLUME) {
                    DEV_BROADCAST_VOLUME* vol = (DEV_BROADCAST_VOLUME*)lp;
                    std::string letters = unitmask_to_letters(vol->dbcv_unitmask);
                    std::string drive = letters.empty() ? "" :
                        (std::string(1, letters[0]) + ":\\");
                    if (wp == DBT_DEVICEARRIVAL) {
                        self->emit("inserted", drive, letters);
                        if (!drive.empty()) self->scan_drive(drive);
                    } else {
                        self->emit("removed", drive, letters);
                    }
                }
            }
        }
        return DefWindowProcW(hwnd, msg, wp, lp);
    };
    wc.hInstance = GetModuleHandleW(nullptr);
    wc.lpszClassName = kClassName;
    RegisterClassW(&wc);

    HWND hwnd = CreateWindowExW(0, kClassName, L"sg-usb", WS_OVERLAPPED, 0, 0, 0, 0,
                                nullptr, nullptr, wc.hInstance, nullptr);
    if (!hwnd) return;
    SetWindowLongPtrW(hwnd, GWLP_USERDATA, (LONG_PTR)this);

    DEV_BROADCAST_DEVICEINTERFACE_W filter;
    std::memset(&filter, 0, sizeof(filter));
    filter.dbcc_size = sizeof(filter);
    filter.dbcc_devicetype = DBT_DEVTYP_DEVICEINTERFACE;
    filter.dbcc_classguid = GUID_SG_VOLUME;
    HDEVNOTIFY hNotify = RegisterDeviceNotificationW(hwnd, &filter,
                                                     DEVICE_NOTIFY_WINDOW_HANDLE);

    MSG msg;
    while (running_.load() && GetMessageW(&msg, nullptr, 0, 0) > 0) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    if (hNotify) UnregisterDeviceNotification(hNotify);
    DestroyWindow(hwnd);
    UnregisterClassW(kClassName, wc.hInstance);
}

#else /* __linux__ */

void UsbMonitor::worker_thread() {
    /* 轮询 /proc/partitions 与常见挂载目录，比较增量 */
    std::vector<std::string> mounts = {"/media", "/run/media", "/mnt"};
    std::set<std::string> seen;
    for (const auto& m : mounts) {
        std::error_code ec;
        if (fs::exists(m, ec)) {
            for (const auto& e : fs::directory_iterator(m, ec))
                seen.insert(e.path().string());
        }
    }
    std::vector<std::string> known(seen.begin(), seen.end());
    while (running_.load()) {
        std::this_thread::sleep_for(std::chrono::seconds(2));
        std::set<std::string> cur;
        for (const auto& m : mounts) {
            std::error_code ec;
            if (fs::exists(m, ec)) {
                for (const auto& e : fs::directory_iterator(m, ec))
                    cur.insert(e.path().string());
            }
        }
        for (const auto& p : cur) {
            if (std::find(known.begin(), known.end(), p) == known.end()) {
                emit("inserted", p, "usb");
                scan_drive(p + "/");
            }
        }
        for (const auto& p : known) {
            if (cur.find(p) == cur.end())
                emit("removed", p, "usb");
        }
        known.assign(cur.begin(), cur.end());
    }
}

#endif

bool UsbMonitor::start() {
    if (running_.load()) return false;
    running_.store(true);
    thread_ = std::thread(&UsbMonitor::worker_thread, this);
    return true;
}

void UsbMonitor::stop() {
    running_.store(false);
    if (thread_.joinable()) thread_.join();
}
