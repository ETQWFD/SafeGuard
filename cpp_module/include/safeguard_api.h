/*
 * SafeGuard 安全卫士 - C 风格导出接口
 * 供 Python ctypes 直接调用。所有返回 const char* 的字符串
 * 由 DLL 内部持有，调用方使用完毕后必须调用 sg_free_string 释放。
 */
#ifndef SAFEGUARD_API_H
#define SAFEGUARD_API_H

#ifdef _WIN32
  #define SG_API extern "C" __declspec(dllexport)
#else
  #define SG_API extern "C" __attribute__((visibility("default")))
#endif

SG_API int sg_init(const char* clamav_db_dir,
                   const char* yara_rules_path,
                   const char* json_db_path,
                   const char* behavior_rules_path,
                   const char* white_list_path);

SG_API void sg_shutdown();

SG_API const char* sg_version();

/* 扫描单个文件，返回 JSON（见 README 格式说明） */
SG_API const char* sg_scan_file(const char* file_path);

/* 扫描目录，progress_cb 回调进度；返回 JSON 汇总 */
SG_API const char* sg_scan_dir(const char* dir_path,
                               void (*progress_cb)(int cur, int total,
                                                   const char* current_file));

/* 取消进行中的目录扫描 */
SG_API int sg_cancel_scan();

SG_API int sg_start_realtime_monitor(const char* dirs_json,
                                     void (*event_cb)(const char* event_json));
SG_API int sg_stop_realtime_monitor();

SG_API int sg_start_usb_monitor(void (*event_cb)(const char* event_json));
SG_API int sg_stop_usb_monitor();

SG_API int sg_start_registry_monitor(void (*event_cb)(const char* event_json));
SG_API int sg_stop_registry_monitor();

/* 隔离区：加入 / 恢复 / 删除 / 列出，返回 JSON */
SG_API int sg_quarantine_add(const char* file_path);
SG_API int sg_quarantine_restore(const char* id, const char* restore_path);
SG_API int sg_quarantine_delete(const char* id);
SG_API const char* sg_quarantine_list();

/* 可疑进程阻断 / 白名单放行一次 */
SG_API int sg_block_process(const char* pid_or_path);
SG_API int sg_allow_once(const char* file_path);

SG_API const char* sg_clamav_version();
SG_API const char* sg_yara_version();

/* 热重载病毒库 */
SG_API int sg_reload_virus_db(const char* json_db_path,
                              const char* yara_rules_path);

SG_API void sg_free_string(const char* s);

#endif /* SAFEGUARD_API_H */
