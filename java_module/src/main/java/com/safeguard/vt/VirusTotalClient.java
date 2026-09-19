/*
 * vt/VirusTotalClient.java - VirusTotal v3 API 真实查询（OkHttp）
 * 限速 4 次/分钟（免费额度）。API Key 从 config/api_keys.json 读取。
 */
package com.safeguard.vt;

import com.safeguard.util.JsonUtil;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;

public class VirusTotalClient {

    private static final String BASE = "https://www.virustotal.com/api/v3/files/";

    private final String apiKey;
    private final OkHttpClient client;
    private long lastCallMs = 0;
    private static final long MIN_INTERVAL_MS = 15_000; /* 4 次/分钟 */

    public VirusTotalClient(String apiKeysPath) {
        String key = "";
        try {
            String text = new String(Files.readAllBytes(Paths.get(apiKeysPath)),
                                     StandardCharsets.UTF_8);
            JsonUtil.Json root = JsonUtil.parse(text);
            key = root.get("virus_total").asStr().trim();
        } catch (Exception ignored) { }
        this.apiKey = key;
        this.client = new OkHttpClient.Builder()
                .connectTimeout(20, java.util.concurrent.TimeUnit.SECONDS)
                .readTimeout(30, java.util.concurrent.TimeUnit.SECONDS)
                .build();
    }

    public boolean hasApiKey() {
        return apiKey != null && !apiKey.isEmpty();
    }

    private synchronized void throttle() {
        long now = System.currentTimeMillis();
        long wait = MIN_INTERVAL_MS - (now - lastCallMs);
        if (wait > 0) {
            try { Thread.sleep(wait); } catch (InterruptedException ignored) { }
        }
        lastCallMs = System.currentTimeMillis();
    }

    /*
     * 查询文件哈希的 VT 检测结果。返回 JSON：
     * {ok, hash, malicious, suspicious, harmless, undetected, engines, link}
     * 无 API Key 或请求失败时 ok=false 并附 error。
     */
    public JsonUtil.Json query(String hash) {
        JsonUtil.Json out = JsonUtil.Json.ofObj();
        out.put("hash", hash);
        if (!hasApiKey()) {
            out.put("ok", false);
            out.put("error", "no_api_key：请在 config/api_keys.json 填入 VirusTotal API Key");
            return out;
        }
        throttle();
        Request req = new Request.Builder()
                .url(BASE + hash)
                .header("x-apikey", apiKey)
                .header("Accept", "application/json")
                .build();
        try (Response resp = client.newCall(req).execute()) {
            int code = resp.code();
            if (code == 401 || code == 403) {
                out.put("ok", false);
                out.put("error", "api_key_invalid：Key 无效或额度用尽（HTTP " + code + "）");
                return out;
            }
            if (code == 404) {
                out.put("ok", true);
                out.put("found", false);
                out.put("detail", "VirusTotal 数据库中未收录该哈希");
                return out;
            }
            if (code != 200) {
                out.put("ok", false);
                out.put("error", "vt http " + code);
                return out;
            }
            String body = resp.body() == null ? "{}" : resp.body().string();
            JsonUtil.Json root = JsonUtil.parse(body);
            JsonUtil.Json data = root.get("data");
            JsonUtil.Json attrs = data.get("attributes");
            JsonUtil.Json stats = attrs.get("last_analysis_stats");
            JsonUtil.Json results = attrs.get("last_analysis_results");

            out.put("ok", true);
            out.put("found", true);
            out.put("malicious", stats.get("malicious").asLong());
            out.put("suspicious", stats.get("suspicious").asLong());
            out.put("harmless", stats.get("harmless").asLong());
            out.put("undetected", stats.get("undetected").asLong());
            out.put("engines", results.size());
            out.put("first_seen", attrs.get("first_submission_date").asStr());
            out.put("link", "https://www.virustotal.com/gui/file/" + hash);
            return out;
        } catch (IOException e) {
            out.put("ok", false);
            out.put("error", "network_error: " + e.getMessage());
            return out;
        } catch (Exception e) {
            out.put("ok", false);
            out.put("error", "parse_error: " + e.getMessage());
            return out;
        }
    }
}
