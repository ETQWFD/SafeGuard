package com.safeguard.android.core

import android.content.Context
import org.json.JSONArray
import org.json.JSONObject

data class VirusEntry(
    val sha256: String,
    val md5: String,
    val name: String,
    val level: Int,
    val type: String,
    val family: String,
    val source: String,
)

/**
 * 病毒库：从 assets/virus_db/signatures.json 加载（用户自建/更新），
 * 首次启动复制到 filesDir 便于在线更新覆盖。
 */
class VirusDb(private val context: Context) {

    private val entries = HashMap<String, VirusEntry>()

    fun load(): Boolean {
        return try {
            val target = java.io.File(context.filesDir, "virus_db/signatures.json")
            if (!target.exists()) {
                target.parentFile?.mkdirs()
                context.assets.open("virus_db/signatures.json").use { input ->
                    target.outputStream().use { output -> input.copyTo(output) }
                }
            }
            val text = target.readText(Charsets.UTF_8)
            val root = JSONObject(text)
            val arr: JSONArray = root.getJSONArray("entries")
            for (i in 0 until arr.length()) {
                val e = arr.getJSONObject(i)
                val entry = VirusEntry(
                    sha256 = e.optString("sha256", "").lowercase(),
                    md5 = e.optString("md5", "").lowercase(),
                    name = e.optString("name", "Unknown"),
                    level = e.optInt("level", 4),
                    type = e.optString("type", "malware"),
                    family = e.optString("family", "unknown"),
                    source = e.optString("source", "manual"),
                )
                if (entry.sha256.isNotEmpty()) entries[entry.sha256] = entry
                if (entry.md5.isNotEmpty()) entries[entry.md5] = entry
            }
            true
        } catch (e: Exception) {
            false
        }
    }

    fun size(): Int = entries.size

    fun lookup(hash: String): VirusEntry? = entries[hash.lowercase().trim()]
}
