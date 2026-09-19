/*
 * virusdb/DbManager.java - signatures.json 加载、查询与合并去重
 */
package com.safeguard.virusdb;

import com.safeguard.util.JsonUtil;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.HashSet;
import java.util.Set;

public class DbManager {

    private JsonUtil.Json root = JsonUtil.Json.ofObj();
    private String dbPath = "";

    public void load(String path) {
        dbPath = path;
        try {
            String text = new String(Files.readAllBytes(Paths.get(path)),
                                     StandardCharsets.UTF_8);
            root = JsonUtil.parse(text);
        } catch (Exception e) {
            root = JsonUtil.Json.ofObj();
            root.put("version", "empty");
            root.put("updated", "");
            root.put("total", 0);
            root.put("entries", JsonUtil.Json.ofArr());
        }
    }

    public String version() { return root.get("version").asStr(); }
    public String updated() { return root.get("updated").asStr(); }
    public long total() { return root.get("entries").isArr() ? root.get("entries").arr.size() : 0; }

    public JsonUtil.Json findByHash(String hash) {
        hash = hash.trim().toLowerCase();
        JsonUtil.Json entries = root.get("entries");
        if (entries.isArr()) {
            for (JsonUtil.Json e : entries.arr) {
                if (e.get("sha256").asStr().toLowerCase().equals(hash)
                        || e.get("md5").asStr().toLowerCase().equals(hash)) {
                    return e;
                }
            }
        }
        return JsonUtil.Json.nul();
    }

    /* 合并条目（按 sha256 去重），返回新增条数并保存 */
    public int merge(JsonUtil.Json newEntries) {
        if (!newEntries.isArr()) return 0;
        Set<String> seen = new HashSet<>();
        JsonUtil.Json entries = root.get("entries");
        if (entries.isArr()) {
            for (JsonUtil.Json e : entries.arr)
                seen.add(e.get("sha256").asStr().toLowerCase());
        } else {
            entries = JsonUtil.Json.ofArr();
            root.put("entries", entries);
        }
        int added = 0;
        for (JsonUtil.Json e : newEntries.arr) {
            String h = e.get("sha256").asStr().toLowerCase();
            if (h.isEmpty() || seen.contains(h)) continue;
            seen.add(h);
            entries.add(e);
            added++;
        }
        root.put("total", entries.arr.size());
        root.put("updated", Instant.now().toString());
        save();
        return added;
    }

    public void save() {
        try {
            Path p = Paths.get(dbPath);
            if (p.getParent() != null) Files.createDirectories(p.getParent());
            Files.write(p, JsonUtil.dump(root).getBytes(StandardCharsets.UTF_8));
        } catch (Exception ignored) { }
    }
}
