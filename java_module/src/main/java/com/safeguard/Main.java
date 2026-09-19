/*
 * Main.java - SafeGuard 云服务入口
 * 启动 127.0.0.1:17890 本地 HTTP 服务，Python 层通过 requests 调用。
 */
package com.safeguard;

import com.safeguard.i18n.LangService;
import com.safeguard.intel.ThreatIntel;
import com.safeguard.report.ReportGenerator;
import com.safeguard.server.ApiServer;
import com.safeguard.virusdb.DbManager;
import com.safeguard.virusdb.Updater;
import com.safeguard.vt.VirusTotalClient;
import com.safeguard.yara.YaraEngine;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class Main {

    public static String projectRoot = ".";

    public static void main(String[] args) throws Exception {
        if (args.length >= 1) {
            projectRoot = args[0];
        }
        Path root = Paths.get(projectRoot).toAbsolutePath().normalize();
        projectRoot = root.toString();

        System.out.println("[SafeGuard-JAR] project root: " + projectRoot);
        System.out.println("[SafeGuard-JAR] java: " + System.getProperty("java.version"));

        Files.createDirectories(root.resolve("data/virus_db"));
        Files.createDirectories(root.resolve("data/yara_rules"));
        Files.createDirectories(root.resolve("logs"));
        Files.createDirectories(root.resolve("reports"));

        LangService lang = new LangService(root.resolve("lang").toString());
        lang.load("zh_CN");

        DbManager db = new DbManager();
        db.load(root.resolve("data/virus_db/signatures.json").toString());

        VirusTotalClient vt = new VirusTotalClient(
                root.resolve("config/api_keys.json").toString());
        Updater updater = new Updater(root.toString(), db);
        ThreatIntel intel = new ThreatIntel(vt, updater);
        YaraEngine yara = new YaraEngine(root.resolve("data/yara_rules").toString(),
                                         root.resolve("data/virus_db/rules.yar").toString());
        ReportGenerator report = new ReportGenerator(root.toString(), lang);

        ApiServer server = new ApiServer(db, vt, updater, intel, yara, report, lang, root.toString());
        server.start();
    }
}
