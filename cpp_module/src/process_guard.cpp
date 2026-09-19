/*
 * process_guard.cpp - 进程阻断实现
 * Windows：OpenProcess + TerminateProcess（需要管理员权限）；
 *         路径模式通过 Toolhelp32 快照按 exe 路径匹配 PID。
 * Linux：按 /proc 扫描匹配路径后 kill(SIGKILL)。
 * 权限不足时返回 -2，由上层提示用户并降级为"仅报警"。
 */
#include "process_guard.h"

#include <cstdlib>
#include <cstring>
#include <cctype>
#include <cerrno>
#include <string>
#include <filesystem>

#ifdef _WIN32
#include <windows.h>
#include <tlhelp32.h>
#endif

#ifdef __linux__
#include <csignal>
#include <fstream>
#include <dirent.h>
#include <unistd.h>
#endif

namespace ProcessGuard {

#ifdef _WIN32
int block_by_pid(unsigned long pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!h) {
        DWORD err = GetLastError();
        if (err == ERROR_ACCESS_DENIED) return -2;
        return -1;
    }
    BOOL ok = TerminateProcess(h, 1);
    CloseHandle(h);
    return ok ? 0 : -1;
}

int block_by_path(const std::string& path) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return -1;
    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);
    int found = -1;
    if (Process32FirstW(snap, &pe)) {
        do {
            char buf[MAX_PATH] = {0};
            DWORD size = MAX_PATH;
            HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
            if (h) {
                if (QueryFullProcessImageNameW(h, 0, (LPWSTR)buf, &size)) {
                    std::wstring wpath(buf);
                    std::string p(wpath.begin(), wpath.end());
                    if (_stricmp(p.c_str(), path.c_str()) == 0) {
                        found = (int)pe.th32ProcessID;
                    }
                }
                CloseHandle(h);
            }
            if (found > 0) break;
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    if (found < 0) return -1;
    return block_by_pid((unsigned long)found);
}
#endif

#ifdef __linux__
int block_by_path(const std::string& path) {
    std::string target = std::filesystem::absolute(path).string();
    DIR* d = opendir("/proc");
    if (!d) return -1;
    struct dirent* de;
    int result = -1;
    while ((de = readdir(d)) != nullptr) {
        if (de->d_name[0] < '0' || de->d_name[0] > '9') continue;
        std::string pid = de->d_name;
        std::string exe = "/proc/" + pid + "/exe";
        char buf[4096];
        ssize_t n = readlink(exe.c_str(), buf, sizeof buf - 1);
        if (n > 0) {
            buf[n] = 0;
            if (target == std::string(buf)) {
                int rc = kill(std::atoi(pid.c_str()), SIGKILL);
                if (rc == 0 || errno == ESRCH) result = 0;
                else if (errno == EPERM) result = -2;
            }
        }
    }
    closedir(d);
    return result;
}
#endif

int block(const std::string& pid_or_path) {
    /* 纯数字视为 PID */
    bool all_digits = !pid_or_path.empty();
    for (char c : pid_or_path)
        if (!isdigit((unsigned char)c)) { all_digits = false; break; }
    if (all_digits) {
#ifdef _WIN32
        return block_by_pid((unsigned long)std::strtoul(pid_or_path.c_str(), nullptr, 10));
#else
        if (::kill(std::atoi(pid_or_path.c_str()), SIGKILL) == 0) return 0;
        return errno == EPERM ? -2 : -1;
#endif
    }
#ifdef _WIN32
    return block_by_path(pid_or_path);
#else
    return block_by_path(pid_or_path);
#endif
}

} /* namespace ProcessGuard */
