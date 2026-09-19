package com.safeguard.android.core

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File

data class ScanResult(
    val path: String,
    val status: String,        // clean / infected / suspicious / error
    val threatName: String = "",
    val sha256: String = "",
    val md5: String = "",
    val engine: String = "",
)

/** 扫描器：真实哈希计算 + 病毒库比对 + 可选 VirusTotal 云端复核 */
class Scanner(private val db: VirusDb) {

    suspend fun scanFile(file: File, vtClient: VtClient?, useCloud: Boolean): ScanResult =
        withContext(Dispatchers.IO) {
            if (!file.exists() || file.length() > 400 * 1024 * 1024L) {
                return@withContext ScanResult(file.path, "error", engine = "limit")
            }
            val sha = HashUtil.fileSha256(file)
            val md5 = HashUtil.fileMd5(file)

            // 1. 本地哈希病毒库
            val hit = db.lookup(sha) ?: db.lookup(md5)
            if (hit != null) {
                return@withContext ScanResult(
                    file.path, "infected", hit.name, sha, md5, "hash")
            }

            // 2. 云端 VirusTotal 复核（可选，需要 Key）
            if (useCloud && vtClient != null && vtClient.hasKey()) {
                val vt = vtClient.query(sha)
                if (vt.malicious > 0) {
                    return@withContext ScanResult(
                        file.path, "infected", "VT:${vt.malicious} engines",
                        sha, md5, "virustotal")
                }
                if (vt.suspicious > 0) {
                    return@withContext ScanResult(
                        file.path, "suspicious", "VT:${vt.suspicious} suspicious",
                        sha, md5, "virustotal")
                }
            }
            ScanResult(file.path, "clean", sha256 = sha, md5 = md5, engine = "hash")
        }

    suspend fun scanDirectory(root: File, maxDepth: Int = 4,
                              onProgress: (Int, String) -> Unit,
                              vtClient: VtClient?, useCloud: Boolean): List<ScanResult> =
        withContext(Dispatchers.IO) {
            val results = mutableListOf<ScanResult>()
            var count = 0
            val MAX_FILES = 4000            // 最多扫描 4000 个文件，避免扫爆存储
            val SKIP_DIRS = setOf("dcim", "pictures", "movies", "music", "android",
                                  ".thumbnails")
            val queue = ArrayDeque<Pair<File, Int>>()
            queue.add(root to 0)
            while (queue.isNotEmpty()) {
                val (dir, depth) = queue.removeFirst()
                val children = dir.listFiles() ?: continue
                for (child in children) {
                    if (count >= MAX_FILES) return@withContext results
                    if (child.isDirectory) {
                        val n = child.name.lowercase()
                        if (depth < maxDepth && n !in SKIP_DIRS && !child.isHidden)
                            queue.add(child to depth + 1)
                    } else {
                        if (child.length() > 60 * 1024 * 1024L) continue
                        count++
                        val r = scanFile(child, vtClient, useCloud)
                        if (r.status != "clean") results.add(r)
                        onProgress(count, child.name)
                    }
                }
            }
            results
        }
}
