/*
 * process_guard.h - 可疑进程阻断（需管理员权限）
 */
#ifndef SG_PROCESS_GUARD_H
#define SG_PROCESS_GUARD_H

#include <string>

namespace ProcessGuard {

/*
 * 阻断进程：pid_or_path 为数字 PID 或可执行文件路径。
 * 成功返回 0；权限不足返回 -2；其他失败返回 -1。
 */
int block(const std::string& pid_or_path);

} /* namespace ProcessGuard */

#endif /* SG_PROCESS_GUARD_H */
