/*
 * clamav_engine.h - libclamav 引擎封装
 */
#ifndef SG_CLAMAV_ENGINE_H
#define SG_CLAMAV_ENGINE_H

#include <string>
#include <mutex>
#include <memory>

struct cl_engine;   /* ClamAV 前向声明 */

class ClamAVEngine {
public:
    explicit ClamAVEngine(const std::string& db_dir);
    ~ClamAVEngine();

    /* 加载病毒库并编译引擎，返回空串表示成功 */
    std::string initialize();
    void shutdown();
    std::string version() const;

    /*
     * 扫描单个文件。返回：
     *  0   干净
     *  >0  发现病毒（threat_name 填入病毒名）
     *  <0  错误（error 描述）
     */
    int scan_file(const std::string& path, std::string& threat_name,
                  std::string& error, long long& scan_ms);

private:
    std::string db_dir_;
    std::string version_;
    cl_engine* engine_;
    unsigned int sigs_loaded_;
    std::mutex scan_mutex_;
};

#endif /* SG_CLAMAV_ENGINE_H */
