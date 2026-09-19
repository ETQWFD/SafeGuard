/*
 * virusdb/Updater.java - 病毒库在线更新
 * MalwareBazaar API 拉取最新样本哈希；YARA 规则从 GitHub 官方仓库拉取。
 */
package com.safeguard.virusdb;

import com.safeguard.util.JsonUtil;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.TimeUnit;

import okhttp3.FormBody;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.RequestBody;
import okhttp3.Response;

public class Updater {

    private static final String MB_API = "https://mb-api.abuse.ch/api/v1/";
    private static final String[] YARA_URLS = {
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/generic_anomalies.yar",
        "https://raw.githubusercontent.com/Neo23x0/signature-base/master/yara/general_banking_malware.yar",
        "https://raw.githubusercontent.com/Yara-Rules/rules/master/malware/APT_Malware.yar"
    };

    private final String projectRoot;
    private final DbManager db;
    private final OkHttpClient client;

    public Updater(String projectRoot, DbManager db) {
        this.projectRoot = projectRoot;
        this.db = db;
        this.client = new OkHttpClient.Builder()
                .connectTimeout(20, TimeUnit.SECONDS)
                .readTimeout(60, TimeUnit.SECONDS)
                .build();
    }

    /* MalwareBazaar 查询单个哈希 */
    public JsonUtil.Json queryMalwareBazaar(String hash) {
        JsonUtil.Json out = JsonUtil.Json.ofObj();
        out.put("hash", hash);
        try {
            RequestBody form = new FormBody.Builder()
                    .add("query", "get_info")
                    .add("hash", hash)
                    .build();
            Request req = new Request.Builder().url(MB_API).post(form).build();
            try (Response resp = client.newCall(req).execute()) {
                String body = resp.body() == null ? "{}" : resp.body().string();
                JsonUtil.Json root = JsonUtil.parse(body);
                if (root.get("query_status").asStr().equals("ok")) {
                    JsonUtil.Json data = root.get("data");
                    if (data.isArr() && data.arr.size() > 0) {
                        JsonUtil.Json item = data.arr.get(0);
                        out.put("ok", true);
                        out.put("found", true);
                        out.put("signature", item.get("signature").asStr());
                        out.put("tags", item.get("tags"));
                        out.put("first_seen", item.get("first_seen").asStr());
                    } else {
                        out.put("ok", true);
                        out.put("found", false);
                    }
                } else {
                    out.put("ok", false);
                    out.put("error", root.get("query_status").asStr());
                }
            }
        } catch (Exception e) {
            out.put("ok", false);
            out.put("error", e.getMessage());
        }
        return out;
    }

    /* 拉取 MalwareBazaar 最新样本并合并入库 */
    public JsonUtil.Json updateFromMalwareBazaar() {
        JsonUtil.Json out = JsonUtil.Json.ofObj();
        try {
            RequestBody form = new FormBody.Builder()
                    .add("query", "get_recent")
                    .add("selector", "time")
                    .add("limit", "100")
                    .build();
            Request req = new Request.Builder()
                    .url(MB_API)
                    .post(form)
                    .header("User-Agent", "SafeGuard/1.0")
                    .build();
            try (Response resp = client.newCall(req).execute()) {
                String body = resp.body() == null ? "{}" : resp.body().string();
                JsonUtil.Json root = JsonUtil.parse(body);
                if (!root.get("query_status").asStr().equals("ok")) {
                    out.put("ok", false);
                    out.put("error", root.get("query_status").asStr());
                    return out;
                }
                JsonUtil.Json data = root.get("data");
                JsonUtil.Json merged = JsonUtil.Json.ofArr();
                int count = 0;
                if (data.isArr()) {
                    for (JsonUtil.Json item : data.arr) {
                        String hash = item.get("sha256_hash").asStr().trim().toLowerCase();
                        if (hash.isEmpty()) continue;
                        String sig = item.get("signature").asStr();
                        if (sig.isEmpty()) sig = "MalwareBazaar.Sample";
                        JsonUtil.Json entry = JsonUtil.Json.ofObj();
                        entry.put("sha256", hash);
                        entry.put("md5", item.get("md5_hash").asStr());
                        entry.put("name", sig);
                        entry.put("level", 5);
                        entry.put("type", "malware");
                        entry.put("family", item.get("tags").asStr());
                        entry.put("source", "malwarebazaar");
                        entry.put("first_seen", item.get("first_seen").asStr());
                        merged.add(entry);
                        count++;
                    }
                }
                /* 写入原始数据备份 */
                Path raw = Paths.get(projectRoot, "data", "virus_db", "mb_recent.json");
                Files.write(raw, JsonUtil.dump(data).getBytes(StandardCharsets.UTF_8));

                int added = db.merge(merged);
                out.put("ok", true);
                out.put("fetched", count);
                out.put("added", added);
                out.put("total", db.total());
            }
        } catch (Exception e) {
            out.put("ok", false);
            out.put("error", e.getMessage());
        }
        return out;
    }

    /* 拉取 YARA 官方规则 */
    public JsonUtil.Json updateYaraRules() {
        JsonUtil.Json out = JsonUtil.Json.ofObj();
        int ok = 0;
        for (String url : YARA_URLS) {
            try {
                String fname = url.substring(url.lastIndexOf('/') + 1);
                Path target = Paths.get(projectRoot, "data", "yara_rules", fname);
                Request req = new Request.Builder().url(url).build();
                try (Response resp = client.newCall(req).execute()) {
                    if (resp.code() == 200 && resp.body() != null) {
                        Files.write(target, resp.body().bytes());
                        ok++;
                    }
                }
            } catch (IOException ignored) { }
        }
        out.put("ok", ok > 0);
        out.put("downloaded", ok);
        out.put("dir", Paths.get(projectRoot, "data", "yara_rules").toString());
        return out;
    }
}
