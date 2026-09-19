/*
 * clamav_engine.cpp - libclamav 真实引擎集成
 * 调用 cl_engine_new / cl_load / cl_engine_compile / cl_scanfile。
 * 需先安装 clamav 开发库（Windows: vcpkg clamav:x64-windows；Linux: libclamav-dev）。
 */
#include "clamav_engine.h"

#include <clamav.h>
#include <cstring>
#include <chrono>
#include <algorithm>
#include <thread>

ClamAVEngine::ClamAVEngine(const std::string& db_dir)
    : db_dir_(db_dir), engine_(nullptr), sigs_loaded_(0) {
    version_ = cl_retver() ? cl_retver() : "unknown";
}

ClamAVEngine::~ClamAVEngine() {
    shutdown();
}

std::string ClamAVEngine::initialize() {
    engine_ = cl_engine_new();
    if (!engine_)
        return "cl_engine_new failed";

    unsigned int sigs = 0;
    if (db_dir_.empty()) {
        cl_engine_free(engine_);
        engine_ = nullptr;
        return "empty clamav db dir";
    }

    cl_error_t ret = cl_load(db_dir_.c_str(), engine_, &sigs, CL_DB_STDOPT);
    if (ret != CL_SUCCESS) {
        std::string err = "cl_load failed: ";
        err += cl_strerror(ret);
        cl_engine_free(engine_);
        engine_ = nullptr;
        return err;
    }
    sigs_loaded_ = sigs;

    ret = cl_engine_compile(engine_);
    if (ret != CL_SUCCESS) {
        std::string err = "cl_engine_compile failed: ";
        err += cl_strerror(ret);
        cl_engine_free(engine_);
        engine_ = nullptr;
        return err;
    }

    /* 限制单文件扫描上限，避免大文件拖垮实时监控 */
    cl_engine_set_num(engine_, CL_ENGINE_MAX_SCANSIZE, 400 * 1024 * 1024);
    cl_engine_set_num(engine_, CL_ENGINE_MAX_FILESIZE, 300 * 1024 * 1024);
    cl_engine_set_num(engine_, CL_ENGINE_MAX_RECURSION, 16);
    return std::string();
}

void ClamAVEngine::shutdown() {
    if (engine_) {
        cl_engine_free(engine_);
        engine_ = nullptr;
    }
}

std::string ClamAVEngine::version() const {
    return version_;
}

int ClamAVEngine::scan_file(const std::string& path, std::string& threat_name,
                            std::string& error, long long& scan_ms) {
    if (!engine_) {
        error = "clamav engine not loaded";
        return -1;
    }
    std::lock_guard<std::mutex> lk(scan_mutex_);

    auto t0 = std::chrono::steady_clock::now();

    struct cl_scan_options options;
    std::memset(&options, 0, sizeof(options));
    /* 默认选项即可命中 EICAR 与常规签名；保持零值避免归档/启发式误导致卡死 */
    options.general = CL_SCAN_GENERAL_HEURISTICS;

    const char* virname = nullptr;
    unsigned long scanned = 0;

    cl_error_t ret = cl_scanfile(path.c_str(), &virname, &scanned, engine_, &options);

    auto t1 = std::chrono::steady_clock::now();
    scan_ms = (long long)std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();

    if (ret == CL_VIRUS) {
        threat_name = virname ? virname : "unknown-virus";
        return 1;
    }
    if (ret == CL_CLEAN)
        return 0;
    error = std::string("cl_scanfile error: ") + cl_strerror(ret);
    return -1;
}
