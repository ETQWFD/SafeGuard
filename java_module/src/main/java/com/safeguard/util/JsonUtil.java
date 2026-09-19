/*
 * util/JsonUtil.java - 轻量 JSON 解析/序列化（无第三方依赖）
 */
package com.safeguard.util;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public final class JsonUtil {

    private JsonUtil() {}

    /* ---------- 值类型 ---------- */
    public enum Type { NULL, BOOL, NUM, STR, ARR, OBJ }

    public static final class Json {
        public Type type = Type.NULL;
        public boolean bool;
        public double num;
        public String str = "";
        public List<Json> arr;
        public Map<String, Json> obj;

        public static Json nul() { Json j = new Json(); j.type = Type.NULL; return j; }
        public static Json ofBool(boolean v) { Json j = new Json(); j.type = Type.BOOL; j.bool = v; return j; }
        public static Json ofNum(double v) { Json j = new Json(); j.type = Type.NUM; j.num = v; return j; }
        public static Json ofStr(String v) { Json j = new Json(); j.type = Type.STR; j.str = v == null ? "" : v; return j; }
        public static Json ofArr() { Json j = new Json(); j.type = Type.ARR; j.arr = new ArrayList<>(); return j; }
        public static Json ofObj() { Json j = new Json(); j.type = Type.OBJ; j.obj = new LinkedHashMap<>(); return j; }

        public boolean isObj() { return type == Type.OBJ; }
        public boolean isArr() { return type == Type.ARR; }
        public boolean isNull() { return type == Type.NULL; }
        public int size() {
            if (type == Type.ARR && arr != null) return arr.size();
            if (type == Type.OBJ && obj != null) return obj.size();
            return 0;
        }
        public Json at(int i) {
            if (type == Type.ARR && arr != null && i >= 0 && i < arr.size()) return arr.get(i);
            return nul();
        }
        public String asStr() { return type == Type.STR ? str : ""; }
        public boolean asBool() { return type == Type.BOOL && bool; }
        public double asNum() { return type == Type.NUM ? num : 0.0; }
        public long asLong() { return (long) num; }

        public Json get(String key) {
            if (type != Type.OBJ) return nul();
            Json v = obj.get(key);
            return v == null ? nul() : v;
        }
        public boolean has(String key) {
            return type == Type.OBJ && obj.containsKey(key);
        }
        public Json put(String key, Json v) {
            if (type != Type.OBJ) { type = Type.OBJ; obj = new LinkedHashMap<>(); }
            obj.put(key, v);
            return this;
        }
        public Json put(String key, String v) { return put(key, ofStr(v)); }
        public Json put(String key, long v) { return put(key, ofNum(v)); }
        public Json put(String key, int v) { return put(key, ofNum(v)); }
        public Json put(String key, double v) { return put(key, ofNum(v)); }
        public Json put(String key, boolean v) { return put(key, ofBool(v)); }
        public Json add(Json v) {
            if (type != Type.ARR) { type = Type.ARR; arr = new ArrayList<>(); }
            arr.add(v);
            return this;
        }
    }

    /* ---------- 解析 ---------- */
    public static Json parse(String text) {
        Parser p = new Parser(text);
        Json v = p.parseValue();
        p.skipWs();
        if (p.pos != text.length())
            throw new IllegalArgumentException("json: trailing data at " + p.pos);
        return v;
    }

    private static final class Parser {
        final String s;
        int pos = 0;
        Parser(String s) { this.s = s; }

        void skipWs() {
            while (pos < s.length() && Character.isWhitespace(s.charAt(pos))) pos++;
        }
        char peek() { return s.charAt(pos); }
        void expect(char c) {
            if (pos >= s.length() || s.charAt(pos) != c)
                throw new IllegalArgumentException("json: expected '" + c + "' at " + pos);
            pos++;
        }

        Json parseValue() {
            skipWs();
            if (pos >= s.length()) throw new IllegalArgumentException("json: unexpected end");
            char c = peek();
            switch (c) {
                case '{': return parseObject();
                case '[': return parseArray();
                case '"': return parseString();
                case 't': expectWord("true"); return Json.ofBool(true);
                case 'f': expectWord("false"); return Json.ofBool(false);
                case 'n': expectWord("null"); return Json.nul();
                default: return parseNumber();
            }
        }
        void expectWord(String w) {
            if (!s.startsWith(w, pos)) throw new IllegalArgumentException("json: bad literal");
            pos += w.length();
        }
        Json parseObject() {
            Json o = Json.ofObj();
            expect('{');
            skipWs();
            if (pos < s.length() && peek() == '}') { pos++; return o; }
            while (pos < s.length()) {
                skipWs();
                String key = parseString().str;
                skipWs();
                expect(':');
                o.put(key, parseValue());
                skipWs();
                if (pos < s.length() && peek() == ',') { pos++; continue; }
                if (pos < s.length() && peek() == '}') { pos++; break; }
                throw new IllegalArgumentException("json: expected ',' or '}'");
            }
            return o;
        }
        Json parseArray() {
            Json a = Json.ofArr();
            expect('[');
            skipWs();
            if (pos < s.length() && peek() == ']') { pos++; return a; }
            while (pos < s.length()) {
                a.add(parseValue());
                skipWs();
                if (pos < s.length() && peek() == ',') { pos++; continue; }
                if (pos < s.length() && peek() == ']') { pos++; break; }
                throw new IllegalArgumentException("json: expected ',' or ']'");
            }
            return a;
        }
        Json parseString() {
            expect('"');
            StringBuilder sb = new StringBuilder();
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (c == '"') { pos++; return Json.ofStr(sb.toString()); }
                if (c == '\\') {
                    pos++;
                    if (pos >= s.length()) break;
                    char e = s.charAt(pos);
                    switch (e) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            if (pos + 4 >= s.length()) throw new IllegalArgumentException("json: bad \\u");
                            sb.append((char) Integer.parseInt(s.substring(pos + 1, pos + 5), 16));
                            pos += 4;
                            break;
                        default: sb.append(e); break;
                    }
                    pos++;
                } else {
                    sb.append(c);
                    pos++;
                }
            }
            throw new IllegalArgumentException("json: unterminated string");
        }
        Json parseNumber() {
            int start = pos;
            if (pos < s.length() && s.charAt(pos) == '-') pos++;
            while (pos < s.length()) {
                char c = s.charAt(pos);
                if (Character.isDigit(c) || c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-') pos++;
                else break;
            }
            return Json.ofNum(Double.parseDouble(s.substring(start, pos)));
        }
    }

    /* ---------- 序列化 ---------- */
    public static String dump(Json v) {
        StringBuilder sb = new StringBuilder();
        write(sb, v);
        return sb.toString();
    }

    private static void write(StringBuilder sb, Json v) {
        switch (v.type) {
            case NULL: sb.append("null"); break;
            case BOOL: sb.append(v.bool); break;
            case NUM:
                if (v.num == Math.rint(v.num) && Math.abs(v.num) < 9e15)
                    sb.append((long) v.num);
                else
                    sb.append(v.num);
                break;
            case STR:
                sb.append('"').append(escape(v.str)).append('"');
                break;
            case ARR: {
                sb.append('[');
                boolean first = true;
                for (Json e : v.arr) {
                    if (!first) sb.append(',');
                    first = false;
                    write(sb, e);
                }
                sb.append(']');
                break;
            }
            case OBJ: {
                sb.append('{');
                boolean first = true;
                for (Map.Entry<String, Json> e : v.obj.entrySet()) {
                    if (!first) sb.append(',');
                    first = false;
                    sb.append('"').append(escape(e.getKey())).append("\":");
                    write(sb, e.getValue());
                }
                sb.append('}');
                break;
            }
        }
    }

    private static String escape(String s) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                default:
                    if (c < 0x20) sb.append(String.format("\\u%04x", (int) c));
                    else sb.append(c);
            }
        }
        return sb.toString();
    }
}
