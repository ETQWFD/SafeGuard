/*
 * json_util.h - JSON 工具函数
 */
#ifndef SG_JSON_UTIL_H
#define SG_JSON_UTIL_H

#include <string>

namespace JsonUtil {

/* 构造 {"status":"...","detail":"..."} */
std::string error_json(const std::string& status, const std::string& detail);

/* 构造 {"status":"ok","key":"value"} */
std::string ok_json(const std::string& key, const std::string& value);

} /* namespace JsonUtil */

#endif /* SG_JSON_UTIL_H */
