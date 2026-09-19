/*
 * scanner.h - 扫描调度器：单文件 / 多线程目录扫描
 */
#ifndef SG_SCANNER_H
#define SG_SCANNER_H

#include <string>

class ClamAVEngine;
class YaraEngine;
class VirusDb;
class BehaviorRules;
class Whitelist;

namespace Scanner {

/* 单文件扫描，返回 JSON（见 safeguard_api.h 注释） */
std::string scan_file(const std::string& path,
                      ClamAVEngine* clamav, YaraEngine* yara,
                      VirusDb* vdb, BehaviorRules* behavior,
                      Whitelist* whitelist);

/*
 * 目录扫描（多线程），返回 JSON 汇总。
 * progress_cb 可为空。支持取消（cancel()）。
 */
std::string scan_dir(const std::string& dir,
                     void (*progress_cb)(int, int, const char*),
                     ClamAVEngine* clamav, YaraEngine* yara,
                     VirusDb* vdb, BehaviorRules* behavior,
                     Whitelist* whitelist);

/* 请求取消目录扫描 */
void cancel();

} /* namespace Scanner */

#endif /* SG_SCANNER_H */
