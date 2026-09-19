/*
 * i18n/LangService.java - 多语言文案服务（lang/*.json）
 */
package com.safeguard.i18n;

import com.safeguard.util.JsonUtil;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.HashMap;
import java.util.Map;

public class LangService {

    private final String langDir;
    private final Map<String, JsonUtil.Json> cache = new HashMap<>();

    public LangService(String langDir) {
        this.langDir = langDir;
    }

    public boolean load(String lang) {
        if (cache.containsKey(lang)) return true;
        try {
            String text = new String(Files.readAllBytes(
                    Paths.get(langDir, lang + ".json")), StandardCharsets.UTF_8);
            JsonUtil.Json root = JsonUtil.parse(text);
            cache.put(lang, root);
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    public long count(String lang) {
        JsonUtil.Json root = cache.get(lang);
        return root == null ? 0 : root.obj == null ? 0 : root.obj.size();
    }

    public String get(String lang, String key) {
        JsonUtil.Json root = cache.get(lang);
        if (root == null) root = cache.get("zh_CN");
        if (root == null) return key;
        return root.get(key).asStr().isEmpty() ? key : root.get(key).asStr();
    }
}
