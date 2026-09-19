/*
 * server/ApiServer.java - 本地 HTTP 服务（127.0.0.1:17890）
 */
package com.safeguard.server;

import com.safeguard.i18n.LangService;
import com.safeguard.intel.ThreatIntel;
import com.safeguard.report.ReportGenerator;
import com.safeguard.util.JsonUtil;
import com.safeguard.virusdb.DbManager;
import com.safeguard.virusdb.Updater;
import com.safeguard.vt.VirusTotalClient;
import com.safeguard.yara.YaraEngine;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.concurrent.Executors;

public class ApiServer {

    private final DbManager db;
    private final VirusTotalClient vt;
    private final Updater updater;
    private final ThreatIntel intel;
    private final YaraEngine yara;
    private final ReportGenerator report;
    private final LangService lang;
    private final String projectRoot;
    private HttpServer server;

    public ApiServer(DbManager db, VirusTotalClient vt, Updater updater,
                     ThreatIntel intel, YaraEngine yara, ReportGenerator report,
                     LangService lang, String projectRoot) {
        this.db = db;
        this.vt = vt;
        this.updater = updater;
        this.intel = intel;
        this.yara = yara;
        this.report = report;
        this.lang = lang;
        this.projectRoot = projectRoot;
    }

    public void start() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 17890), 0);
        server.setExecutor(Executors.newCachedThreadPool());

        server.createContext("/api/version", this::handleVersion);
        server.createContext("/api/clamav/version", this::handleClamavVersion);
        server.createContext("/api/virusdb/status", this::handleDbStatus);
        server.createContext("/api/virusdb/update", this::handleDbUpdate);
        server.createContext("/api/vt/query", this::handleVtQuery);
        server.createContext("/api/mb/query", this::handleMbQuery);
        server.createContext("/api/yara/scan", this::handleYaraScan);
        server.createContext("/api/intel/query", this::handleIntelQuery);
        server.createContext("/api/i18n/load", this::handleI18nLoad);
        server.createContext("/api/report/generate", this::handleReportGenerate);
        server.createContext("/api/log/archive", this::handleLogArchive);

        server.start();
        System.out.println("[SafeGuard-JAR] HTTP service running on http://127.0.0.1:17890");
    }

    public void stop() {
        if (server != null) server.stop(0);
    }

    /* ---------------- 路由实现 ---------------- */

    private void handleVersion(HttpExchange ex) throws IOException {
        JsonUtil.Json o = JsonUtil.Json.ofObj();
        o.put("name", "SafeGuard Cloud Service");
        o.put("version", "1.0.0");
        o.put("ok", true);
        respond(ex, 200, o);
    }

    private void handleClamavVersion(HttpExchange ex) throws IOException {
        JsonUtil.Json o = JsonUtil.Json.ofObj();
        o.put("clamav", "引擎版本由本地 C++ DLL 提供（Java 端不内置 ClamAV）");
        o.put("yara_cli", yara.version());
        respond(ex, 200, o);
    }

    private void handleDbStatus(HttpExchange ex) throws IOException {
        JsonUtil.Json o = JsonUtil.Json.ofObj();
        o.put("version", db.version());
        o.put("updated", db.updated());
        o.put("total", db.total());
        o.put("ok", true);
        respond(ex, 200, o);
    }

    private void handleDbUpdate(HttpExchange ex) throws IOException {
        JsonUtil.Json body = readBody(ex);
        String mode = body.get("mode").asStr();
        if (mode == null || mode.isEmpty()) mode = "all";
        JsonUtil.Json result = JsonUtil.Json.ofObj();
        if (mode.equals("mb") || mode.equals("all")) {
            JsonUtil.Json r = updater.updateFromMalwareBazaar();
            result.put("malwarebazaar", r);
        }
        if (mode.equals("yara") || mode.equals("all")) {
            JsonUtil.Json r = updater.updateYaraRules();
            result.put("yara", r);
        }
        result.put("ok", true);
        respond(ex, 200, result);
    }

    private void handleVtQuery(HttpExchange ex) throws IOException {
        JsonUtil.Json body = readBody(ex);
        String hash = body.get("sha256").asStr().trim().toLowerCase();
        if (hash.isEmpty()) {
            respond(ex, 400, err("missing sha256"));
            return;
        }
        respond(ex, 200, vt.query(hash));
    }

    private void handleMbQuery(HttpExchange ex) throws IOException {
        JsonUtil.Json body = readBody(ex);
        String hash = body.get("sha256").asStr().trim().toLowerCase();
        if (hash.isEmpty()) {
            respond(ex, 400, err("missing sha256"));
            return;
        }
        respond(ex, 200, updater.queryMalwareBazaar(hash));
    }

    private void handleYaraScan(HttpExchange ex) throws IOException {
        JsonUtil.Json body = readBody(ex);
        String file = body.get("file").asStr();
        if (file.isEmpty()) {
            respond(ex, 400, err("missing file"));
            return;
        }
        respond(ex, 200, yara.scanFile(file));
    }

    private void handleIntelQuery(HttpExchange ex) throws IOException {
        JsonUtil.Json body = readBody(ex);
        String hash = body.get("hash").asStr().trim().toLowerCase();
        if (hash.isEmpty()) {
            respond(ex, 400, err("missing hash"));
            return;
        }
        respond(ex, 200, intel.query(hash));
    }

    private void handleI18nLoad(HttpExchange ex) throws IOException {
        JsonUtil.Json body = readBody(ex);
        String langName = body.get("lang").asStr();
        if (langName.isEmpty()) langName = "zh_CN";
        JsonUtil.Json o = JsonUtil.Json.ofObj();
        o.put("lang", langName);
        o.put("loaded", lang.load(langName));
        o.put("keys", lang.count(langName));
        respond(ex, 200, o);
    }

    private void handleReportGenerate(HttpExchange ex) throws IOException {
        JsonUtil.Json body = readBody(ex);
        respond(ex, 200, report.generate(body));
    }

    private void handleLogArchive(HttpExchange ex) throws IOException {
        JsonUtil.Json body = readBody(ex);
        String tag = body.get("tag").asStr();
        JsonUtil.Json o = JsonUtil.Json.ofObj();
        try {
            Path logs = Paths.get(projectRoot, "logs");
            Path archive = Paths.get(projectRoot, "logs", "archive");
            Files.createDirectories(archive);
            String stamp = new java.text.SimpleDateFormat("yyyyMMdd-HHmmss").format(new java.util.Date());
            String zipName = "logs-" + stamp + (tag.isEmpty() ? "" : "-" + tag) + ".zip";
            Path zipPath = archive.resolve(zipName);
            try (java.util.zip.ZipOutputStream zos =
                         new java.util.zip.ZipOutputStream(Files.newOutputStream(zipPath))) {
                if (Files.exists(logs)) {
                    try (java.util.stream.Stream<Path> list = Files.list(logs)) {
                        list.filter(p -> p.getFileName().toString().endsWith(".log"))
                            .forEach(p -> {
                                try {
                                    zos.putNextEntry(new java.util.zip.ZipEntry(p.getFileName().toString()));
                                    Files.copy(p, zos);
                                    zos.closeEntry();
                                } catch (IOException ignored) { }
                            });
                    }
                }
            }
            o.put("ok", true);
            o.put("archive", zipPath.toString());
        } catch (Exception e) {
            o.put("ok", false);
            o.put("error", e.getMessage());
        }
        respond(ex, 200, o);
    }

    /* ---------------- 工具 ---------------- */

    private JsonUtil.Json readBody(HttpExchange ex) throws IOException {
        try (InputStream in = ex.getRequestBody()) {
            byte[] data = in.readAllBytes();
            String text = new String(data, StandardCharsets.UTF_8);
            if (text.trim().isEmpty()) return JsonUtil.Json.ofObj();
            try {
                return JsonUtil.parse(text);
            } catch (Exception e) {
                return JsonUtil.Json.ofObj();
            }
        }
    }

    private JsonUtil.Json err(String msg) {
        JsonUtil.Json o = JsonUtil.Json.ofObj();
        o.put("ok", false);
        o.put("error", msg);
        return o;
    }

    private void respond(HttpExchange ex, int code, JsonUtil.Json payload) throws IOException {
        byte[] bytes = JsonUtil.dump(payload).getBytes(StandardCharsets.UTF_8);
        ex.getResponseHeaders().set("Content-Type", "application/json; charset=utf-8");
        ex.sendResponseHeaders(code, bytes.length);
        try (OutputStream os = ex.getResponseBody()) {
            os.write(bytes);
        }
    }
}
