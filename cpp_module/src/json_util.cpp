/*
 * json_util.cpp - JSON 工具函数（结果构造辅助）
 */
#include "json_util.h"

#include "../third_party/json.hpp"

namespace JsonUtil {

std::string error_json(const std::string& status, const std::string& detail) {
    sg::Json o = sg::Json::make_object();
    o["status"] = sg::Json::make_string(status);
    o["detail"] = sg::Json::make_string(detail);
    return o.dump();
}

std::string ok_json(const std::string& key, const std::string& value) {
    sg::Json o = sg::Json::make_object();
    o["status"] = sg::Json::make_string("ok");
    o[key] = sg::Json::make_string(value);
    return o.dump();
}

} /* namespace JsonUtil */
