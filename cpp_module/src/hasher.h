/*
 * hasher.h - SHA-256 / MD5 真实哈希计算（纯 C++ 实现，无外部依赖）
 */
#ifndef SG_HASHER_H
#define SG_HASHER_H

#include <string>
#include <cstdint>

namespace Hasher {

/* 计算文件 SHA-256，返回 64 位小写十六进制；失败返回空串 */
std::string file_sha256(const std::string& path);

/* 计算文件 MD5，返回 32 位小写十六进制；失败返回空串 */
std::string file_md5(const std::string& path);

/* 计算字符串 SHA-256（测试用） */
std::string str_sha256(const std::string& data);

/* 计算字符串 MD5（测试用） */
std::string str_md5(const std::string& data);

} /* namespace Hasher */

#endif /* SG_HASHER_H */
