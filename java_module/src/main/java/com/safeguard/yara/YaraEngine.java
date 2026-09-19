/*
 * yara/YaraEngine.java - YARA 规则引擎辅助
 * 调用本地安装的 yara 命令行工具扫描文件（真实规则匹配）。
 * 未安装 yara CLI 时返回 unavailable，由 Python 层回退到 DLL 内嵌引擎。
 */
package com.safeguard.yara;

import com.safeguard.util.JsonUtil;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;

public class YaraEngine {

    private final String rulesDir;
    private final String rulesFile;

    public YaraEngine(String rulesDir, String rulesFile) {
        this.rulesDir = rulesDir;
        this.rulesFile = rulesFile;
    }

    public String version() {
        try {
            Process p = new ProcessBuilder("yara", "--version").redirectErrorStream(true).start();
            try (BufferedReader r = new BufferedReader(
                         new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                String line = r.readLine();
                p.waitFor();
                return line == null ? "yara CLI 未安装" : line.trim();
            }
        } catch (Exception e) {
            return "yara CLI 未安装";
        }
    }

    /*
     * 扫描文件，返回 JSON：
     * {ok, status: clean|suspicious|unavailable, matches:["rule1",...]}
     */
    public JsonUtil.Json scanFile(String filePath) {
        JsonUtil.Json out = JsonUtil.Json.ofObj();
        if (!Files.exists(Paths.get(filePath))) {
            out.put("ok", false);
            out.put("error", "file not found: " + filePath);
            return out;
        }
        String rules = rulesFile;
        if (!Files.exists(Paths.get(rules))) {
            /* 回退：扫描规则目录下所有 .yar */
            rules = rulesDir;
        }
        try {
            ProcessBuilder pb = new ProcessBuilder("yara", "-w", rules, filePath);
            pb.redirectErrorStream(true);
            Process p = pb.start();
            JsonUtil.Json matches = JsonUtil.Json.ofArr();
            String line;
            try (BufferedReader r = new BufferedReader(
                         new InputStreamReader(p.getInputStream(), StandardCharsets.UTF_8))) {
                while ((line = r.readLine()) != null) {
                    line = line.trim();
                    if (!line.isEmpty()) {
                        int sp = line.indexOf(' ');
                        matches.add(JsonUtil.Json.ofStr(
                                sp > 0 ? line.substring(0, sp) : line));
                    }
                }
            }
            int code = p.waitFor();
            out.put("ok", true);
            if (code == 0) {
                out.put("status", matches.size() > 0 ? "suspicious" : "clean");
                out.put("matches", matches);
            } else {
                out.put("status", "error");
                out.put("error", "yara exit code " + code);
            }
            return out;
        } catch (Exception e) {
            out.put("ok", true);
            out.put("status", "unavailable");
            out.put("error", "yara CLI 不可用: " + e.getMessage());
            return out;
        }
    }
}
