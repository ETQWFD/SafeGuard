/*
 * json.hpp - SafeGuard 自包含 JSON 库（单头文件，无第三方依赖）
 * 支持解析与序列化 null/bool/number/string/array/object。
 * 数字统一以 double 存储，序列化时尽量保留整数形式。
 */
#ifndef SG_JSON_HPP
#define SG_JSON_HPP

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <cstdint>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

namespace sg {

class Json {
public:
    enum Type { NUL, BOOL, NUM, STR, ARR, OBJ };

    Json() : type_(NUL), bool_(false), num_(0.0) {}
    Json(const Json& o) { copy(o); }
    Json(Json&& o) noexcept { move(std::move(o)); }
    Json& operator=(const Json& o) { if (this != &o) { clear(); copy(o); } return *this; }
    Json& operator=(Json&& o) noexcept { if (this != &o) { clear(); move(std::move(o)); } return *this; }
    ~Json() { clear(); }

    static Json make_null() { return Json(); }
    static Json make_bool(bool v) { Json j; j.type_ = BOOL; j.bool_ = v; return j; }
    static Json make_number(double v) { Json j; j.type_ = NUM; j.num_ = v; return j; }
    static Json make_string(const std::string& v) { Json j; j.type_ = STR; j.str_ = v; return j; }
    static Json make_array() { Json j; j.type_ = ARR; return j; }
    static Json make_object() { Json j; j.type_ = OBJ; return j; }

    Type type() const { return type_; }
    bool is_null() const { return type_ == NUL; }
    bool is_bool() const { return type_ == BOOL; }
    bool is_number() const { return type_ == NUM; }
    bool is_string() const { return type_ == STR; }
    bool is_array() const { return type_ == ARR; }
    bool is_object() const { return type_ == OBJ; }

    bool as_bool() const { return type_ == BOOL && bool_; }
    double as_number() const { return type_ == NUM ? num_ : 0.0; }
    long long as_int() const { return (long long)num_; }
    const std::string& as_string() const { static const std::string empty; return type_ == STR ? str_ : empty; }

    Json& operator[](const std::string& key) {
        if (type_ != OBJ) { clear(); type_ = OBJ; }
        return obj_[key];
    }
    const Json& at(const std::string& key) const {
        static const Json nul;
        if (type_ != OBJ) return nul;
        auto it = obj_.find(key);
        return it == obj_.end() ? nul : it->second;
    }
    bool has(const std::string& key) const {
        return type_ == OBJ && obj_.find(key) != obj_.end();
    }

    Json& operator[](size_t idx) {
        if (type_ != ARR) { clear(); type_ = ARR; }
        while (arr_.size() <= idx) arr_.push_back(Json());
        return arr_[idx];
    }
    const Json& operator[](size_t idx) const {
        static const Json nul;
        if (type_ != ARR || idx >= arr_.size()) return nul;
        return arr_[idx];
    }
    void push_back(const Json& v) {
        if (type_ != ARR) { clear(); type_ = ARR; }
        arr_.push_back(v);
    }
    size_t size() const { return type_ == ARR ? arr_.size() : (type_ == OBJ ? obj_.size() : 0); }
    const std::vector<Json>& array() const { static const std::vector<Json> empty; return type_ == ARR ? arr_ : empty; }
    const std::map<std::string, Json>& object() const { static const std::map<std::string, Json> empty; return type_ == OBJ ? obj_ : empty; }

    /* ---------- 序列化 ---------- */
    std::string dump() const {
        std::string out;
        write(out, *this);
        return out;
    }

    /* ---------- 解析 ---------- */
    static Json parse(const std::string& text) {
        size_t pos = 0;
        Json v = parse_value(text, pos);
        skip_ws(text, pos);
        if (pos != text.size())
            throw std::runtime_error("json: trailing data at " + std::to_string(pos));
        return v;
    }

private:
    Type type_;
    bool bool_;
    double num_;
    std::string str_;
    std::vector<Json> arr_;
    std::map<std::string, Json> obj_;

    void clear() {
        type_ = NUL; bool_ = false; num_ = 0.0;
        str_.clear(); arr_.clear(); obj_.clear();
    }
    void copy(const Json& o) {
        type_ = o.type_; bool_ = o.bool_; num_ = o.num_;
        str_ = o.str_; arr_ = o.arr_; obj_ = o.obj_;
    }
    void move(Json&& o) {
        type_ = o.type_; bool_ = o.bool_; num_ = o.num_;
        str_ = std::move(o.str_); arr_ = std::move(o.arr_); obj_ = std::move(o.obj_);
        o.type_ = NUL;
    }

    static void skip_ws(const std::string& s, size_t& p) {
        while (p < s.size() && (s[p] == ' ' || s[p] == '\t' || s[p] == '\n' || s[p] == '\r')) ++p;
    }

    static std::string escape_str(const std::string& s) {
        std::string out = "\"";
        for (size_t i = 0; i < s.size(); ++i) {
            unsigned char c = (unsigned char)s[i];
            switch (c) {
                case '"': out += "\\\""; break;
                case '\\': out += "\\\\"; break;
                case '\b': out += "\\b"; break;
                case '\f': out += "\\f"; break;
                case '\n': out += "\\n"; break;
                case '\r': out += "\\r"; break;
                case '\t': out += "\\t"; break;
                default:
                    if (c < 0x20) {
                        char buf[8]; snprintf(buf, sizeof buf, "\\u%04x", c);
                        out += buf;
                    } else {
                        out += (char)c;
                    }
            }
        }
        out += "\"";
        return out;
    }

    static void write(std::string& out, const Json& v) {
        switch (v.type_) {
            case NUL: out += "null"; break;
            case BOOL: out += v.bool_ ? "true" : "false"; break;
            case NUM: {
                if (v.num_ == (double)(long long)v.num_ && std::fabs(v.num_) < 9.0e15) {
                    out += std::to_string((long long)v.num_);
                } else {
                    char buf[32]; snprintf(buf, sizeof buf, "%.9g", v.num_);
                    out += buf;
                }
                break;
            }
            case STR: out += escape_str(v.str_); break;
            case ARR: {
                out += "[";
                for (size_t i = 0; i < v.arr_.size(); ++i) {
                    if (i) out += ",";
                    write(out, v.arr_[i]);
                }
                out += "]";
                break;
            }
            case OBJ: {
                out += "{";
                bool first = true;
                for (auto& kv : v.obj_) {
                    if (!first) out += ",";
                    first = false;
                    out += escape_str(kv.first);
                    out += ":";
                    write(out, kv.second);
                }
                out += "}";
                break;
            }
        }
    }

    static Json parse_value(const std::string& s, size_t& p) {
        skip_ws(s, p);
        if (p >= s.size()) throw std::runtime_error("json: unexpected end");
        char c = s[p];
        if (c == '{') return parse_object(s, p);
        if (c == '[') return parse_array(s, p);
        if (c == '"') return parse_string(s, p);
        if (c == 't' || c == 'f') return parse_bool(s, p);
        if (c == 'n') return parse_null(s, p);
        if (c == '-' || (c >= '0' && c <= '9')) return parse_number(s, p);
        throw std::runtime_error(std::string("json: unexpected char '") + c + "' at " + std::to_string(p));
    }

    static Json parse_object(const std::string& s, size_t& p) {
        Json obj = make_object();
        ++p;
        skip_ws(s, p);
        if (p < s.size() && s[p] == '}') { ++p; return obj; }
        while (p < s.size()) {
            skip_ws(s, p);
            if (p >= s.size() || s[p] != '"') throw std::runtime_error("json: expected key string");
            std::string key = parse_string(s, p).str_;
            skip_ws(s, p);
            if (p >= s.size() || s[p] != ':') throw std::runtime_error("json: expected ':'");
            ++p;
            obj[key] = parse_value(s, p);
            skip_ws(s, p);
            if (p < s.size() && s[p] == ',') { ++p; continue; }
            if (p < s.size() && s[p] == '}') { ++p; break; }
            throw std::runtime_error("json: expected ',' or '}'");
        }
        return obj;
    }

    static Json parse_array(const std::string& s, size_t& p) {
        Json arr = make_array();
        ++p;
        skip_ws(s, p);
        if (p < s.size() && s[p] == ']') { ++p; return arr; }
        while (p < s.size()) {
            arr.push_back(parse_value(s, p));
            skip_ws(s, p);
            if (p < s.size() && s[p] == ',') { ++p; continue; }
            if (p < s.size() && s[p] == ']') { ++p; break; }
            throw std::runtime_error("json: expected ',' or ']'");
        }
        return arr;
    }

    static Json parse_string(const std::string& s, size_t& p) {
        ++p; /* opening quote */
        std::string out;
        while (p < s.size()) {
            unsigned char c = (unsigned char)s[p];
            if (c == '"') { ++p; return make_string(out); }
            if (c == '\\') {
                ++p;
                if (p >= s.size()) break;
                char e = s[p];
                switch (e) {
                    case '"': out += '"'; break;
                    case '\\': out += '\\'; break;
                    case '/': out += '/'; break;
                    case 'b': out += '\b'; break;
                    case 'f': out += '\f'; break;
                    case 'n': out += '\n'; break;
                    case 'r': out += '\r'; break;
                    case 't': out += '\t'; break;
                    case 'u': {
                        if (p + 4 >= s.size()) throw std::runtime_error("json: bad \\u escape");
                        unsigned int code = 0;
                        for (int i = 0; i < 4; ++i) {
                            char h = s[p + 1 + i];
                            code <<= 4;
                            if (h >= '0' && h <= '9') code |= (unsigned int)(h - '0');
                            else if (h >= 'a' && h <= 'f') code |= (unsigned int)(h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') code |= (unsigned int)(h - 'A' + 10);
                            else throw std::runtime_error("json: bad \\u hex");
                        }
                        p += 4;
                        /* 仅支持 BMP；UTF-8 编码 */
                        if (code < 0x80) out += (char)code;
                        else if (code < 0x800) {
                            out += (char)(0xC0 | (code >> 6));
                            out += (char)(0x80 | (code & 0x3F));
                        } else {
                            out += (char)(0xE0 | (code >> 12));
                            out += (char)(0x80 | ((code >> 6) & 0x3F));
                            out += (char)(0x80 | (code & 0x3F));
                        }
                        break;
                    }
                    default: out += e; break;
                }
                ++p;
            } else {
                out += (char)c;
                ++p;
            }
        }
        throw std::runtime_error("json: unterminated string");
    }

    static Json parse_bool(const std::string& s, size_t& p) {
        if (s.compare(p, 4, "true") == 0) { p += 4; return make_bool(true); }
        if (s.compare(p, 5, "false") == 0) { p += 5; return make_bool(false); }
        throw std::runtime_error("json: bad bool");
    }

    static Json parse_null(const std::string& s, size_t& p) {
        if (s.compare(p, 4, "null") == 0) { p += 4; return make_null(); }
        throw std::runtime_error("json: bad null");
    }

    static Json parse_number(const std::string& s, size_t& p) {
        size_t start = p;
        if (p < s.size() && s[p] == '-') ++p;
        while (p < s.size() && (isdigit((unsigned char)s[p]) || s[p] == '.' || s[p] == 'e' || s[p] == 'E' || s[p] == '+' || s[p] == '-')) ++p;
        std::string tok = s.substr(start, p - start);
        char* end = nullptr;
        double d = strtod(tok.c_str(), &end);
        if (!end || *end != '\0') throw std::runtime_error("json: bad number");
        return make_number(d);
    }
};

} /* namespace sg */

#endif /* SG_JSON_HPP */
