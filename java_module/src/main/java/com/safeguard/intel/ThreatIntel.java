/*
 * intel/ThreatIntel.java - 威胁情报聚合（VirusTotal + MalwareBazaar）
 */
package com.safeguard.intel;

import com.safeguard.util.JsonUtil;
import com.safeguard.virusdb.Updater;
import com.safeguard.vt.VirusTotalClient;

public class ThreatIntel {

    private final VirusTotalClient vt;
    private final Updater updater;

    public ThreatIntel(VirusTotalClient vt, Updater updater) {
        this.vt = vt;
        this.updater = updater;
    }

    /*
     * 聚合查询。返回 JSON：
     * {ok, hash, virus_total:{...}, malwarebazaar:{...},
     *  verdict: malicious|suspicious|clean|unknown, score}
     */
    public JsonUtil.Json query(String hash) {
        JsonUtil.Json out = JsonUtil.Json.ofObj();
        out.put("hash", hash);

        JsonUtil.Json vtResult = vt.query(hash);
        JsonUtil.Json mbResult = updater.queryMalwareBazaar(hash);

        out.put("virus_total", vtResult);
        out.put("malwarebazaar", mbResult);

        /* 简单判定 */
        long malicious = vtResult.get("malicious").asLong();
        long suspicious = vtResult.get("suspicious").asLong();
        boolean mbFound = mbResult.get("found").asBool();

        String verdict;
        long score;
        if (malicious > 0) {
            verdict = "malicious";
            score = malicious;
        } else if (suspicious > 0) {
            verdict = "suspicious";
            score = suspicious;
        } else if (mbFound) {
            verdict = "suspicious";
            score = 1;
        } else if (vtResult.get("found").asBool()) {
            verdict = "clean";
            score = 0;
        } else {
            verdict = "unknown";
            score = 0;
        }
        out.put("verdict", verdict);
        out.put("score", score);
        return out;
    }
}
