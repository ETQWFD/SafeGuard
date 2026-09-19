/*
 * report/ReportGenerator.java - 扫描报告生成（HTML + PDF）
 * HTML：完整可视化报告；PDF：内置轻量文本 PDF 写入器（无需第三方库）。
 */
package com.safeguard.report;

import com.safeguard.i18n.LangService;
import com.safeguard.util.JsonUtil;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class ReportGenerator {

    private final String projectRoot;
    private final LangService lang;

    public ReportGenerator(String projectRoot, LangService lang) {
        this.projectRoot = projectRoot;
        this.lang = lang;
    }

    public JsonUtil.Json generate(JsonUtil.Json body) {
        JsonUtil.Json out = JsonUtil.Json.ofObj();
        try {
            String stamp = new SimpleDateFormat("yyyyMMdd-HHmmss").format(new Date());
            Path reportDir = Paths.get(projectRoot, "reports");
            Files.createDirectories(reportDir);

            /* 摘要数据 */
            long scanned = body.get("scanned").asLong();
            long infected = body.get("infected_count").asLong();
            long suspicious = body.get("suspicious_count").asLong();
            String mode = body.get("mode").asStr();
            if (mode.isEmpty()) mode = "manual";
            String threatList = body.get("threats").asStr();

            String title = "SafeGuard 扫描报告 " + stamp;
            String html = buildHtml(title, stamp, mode, scanned, infected, suspicious, threatList);
            Path htmlPath = reportDir.resolve("report-" + stamp + ".html");
            Files.write(htmlPath, html.getBytes(StandardCharsets.UTF_8));

            Path pdfPath = reportDir.resolve("report-" + stamp + ".pdf");
            buildPdf(pdfPath, title, stamp, mode, scanned, infected, suspicious, threatList);

            out.put("ok", true);
            out.put("html", htmlPath.toString());
            out.put("pdf", pdfPath.toString());
            out.put("report_dir", reportDir.toString());
        } catch (Exception e) {
            out.put("ok", false);
            out.put("error", e.getMessage());
        }
        return out;
    }

    private String esc(String s) {
        if (s == null) return "";
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private String buildHtml(String title, String stamp, String mode,
                             long scanned, long infected, long suspicious,
                             String threats) {
        StringBuilder sb = new StringBuilder();
        sb.append("<!DOCTYPE html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">");
        sb.append("<title>").append(esc(title)).append("</title>");
        sb.append("<style>body{font-family:'Segoe UI',system-ui,sans-serif;background:#f5f7fb;");
        sb.append("color:#1f2937;margin:0;padding:32px;}");
        sb.append(".card{background:#fff;border-radius:14px;box-shadow:0 4px 18px rgba(74,144,226,.12);");
        sb.append("padding:28px;max-width:860px;margin:0 auto 20px;}");
        sb.append("h1{color:#1d4ed8;font-size:22px;margin:0 0 6px;}");
        sb.append(".meta{color:#6b7280;font-size:13px;margin-bottom:20px;}");
        sb.append(".grid{display:flex;gap:16px;margin:18px 0;}");
        sb.append(".stat{flex:1;background:#eef4ff;border-radius:10px;padding:16px;text-align:center;}");
        sb.append(".stat b{display:block;font-size:28px;color:#1d4ed8;}");
        sb.append(".stat span{font-size:12px;color:#6b7280;}");
        sb.append("pre{background:#0f172a;color:#e2e8f0;border-radius:10px;padding:16px;");
        sb.append("overflow:auto;font-size:12px;white-space:pre-wrap;word-break:break-all;}</style>");
        sb.append("</head><body>");
        sb.append("<div class=\"card\"><h1>").append(esc(title)).append("</h1>");
        sb.append("<div class=\"meta\">生成时间：").append(esc(stamp))
          .append(" ｜ 扫描方式：").append(esc(mode)).append("</div>");
        sb.append("<div class=\"grid\">");
        sb.append("<div class=\"stat\"><b>").append(scanned).append("</b><span>扫描文件</span></div>");
        sb.append("<div class=\"stat\"><b>").append(infected).append("</b><span>已感染</span></div>");
        sb.append("<div class=\"stat\"><b>").append(suspicious).append("</b><span>可疑</span></div>");
        sb.append("</div>");
        if (threats != null && !threats.isEmpty()) {
            sb.append("<h3>威胁明细</h3><pre>").append(esc(threats)).append("</pre>");
        }
        sb.append("<p style=\"font-size:12px;color:#9ca3af;\">本报告由 SafeGuard 安全卫士生成。</p>");
        sb.append("</div></body></html>");
        return sb.toString();
    }

    /* 轻量 PDF 文本写入器（Helvetica 内建字体） */
    private void buildPdf(Path path, String title, String stamp, String mode,
                          long scanned, long infected, long suspicious,
                          String threats) throws Exception {
        List<String> lines = new ArrayList<>();
        lines.add(title);
        lines.add("Generated: " + stamp + "  Mode: " + mode);
        lines.add("");
        lines.add("Scanned: " + scanned);
        lines.add("Infected: " + infected);
        lines.add("Suspicious: " + suspicious);
        lines.add("");
        if (threats != null && !threats.isEmpty()) {
            for (String l : threats.split("\n"))
                lines.add(l);
        }
        lines.add("");
        lines.add("Generated by SafeGuard Security Guard");

        StringBuilder content = new StringBuilder();
        float y = 780;
        for (String l : lines) {
            content.append("BT /F1 11 Tf 56 ").append(y).append(" Td (")
                   .append(escapePdf(l)).append(") Tj ET\n");
            y -= 18;
            if (y < 60) break;
        }

        int objects = 4;
        StringBuilder pdf = new StringBuilder();
        pdf.append("%PDF-1.4\n");
        int offset = 0;
        int[] offs = new int[objects + 1];
        for (int i = 1; i <= objects; i++) {
            offs[i] = offset;
            switch (i) {
                case 1:
                    pdf.append("1 0 obj<</Type/Catalog/Pages 2 0 R>>endobj\n");
                    break;
                case 2:
                    pdf.append("2 0 obj<</Type/Pages/Kids[3 0 R]/Count 1>>endobj\n");
                    break;
                case 3:
                    pdf.append("3 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 595 842]")
                       .append("/Resources<</Font<</F1 4 0 R>>>>/Contents 5 0 R>>endobj\n");
                    break;
                case 4:
                    pdf.append("4 0 obj<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>endobj\n");
                    break;
            }
            offset += pdf.length() - offset;
        }
        /* object 5：内容流 */
        offs[5] = pdf.length();
        pdf.append("5 0 obj<</Length ").append(content.length())
           .append(">>stream\n").append(content).append("endstream\nendobj\n");
        int xref = pdf.length();
        pdf.append("xref\n0 ").append(objects + 1).append("\n");
        pdf.append("0000000000 65535 f \n");
        for (int i = 1; i <= objects; i++)
            pdf.append(String.format("%010d 00000 n \n", offs[i]));
        pdf.append("trailer<</Size ").append(objects + 1)
           .append("/Root 1 0 R>>\nstartxref\n").append(xref).append("\n%%EOF\n");
        Files.write(path, pdf.toString().getBytes(StandardCharsets.ISO_8859_1));
    }

    private String escapePdf(String s) {
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)");
    }
}
