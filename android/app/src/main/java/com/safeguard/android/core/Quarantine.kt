package com.safeguard.android.core

import android.content.Context
import java.io.File
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale

/**
 * 隔离区：把文件移动到应用私有目录（Android 沙箱内加密存储），
 * 记录元数据 JSON，支持恢复与彻底删除。
 */
class Quarantine(private val context: Context) {

    private val root = File(context.filesDir, "quarantine")
    private val metaDir = File(root, "meta")

    init {
        metaDir.mkdirs()
    }

    fun add(file: File): Boolean {
        return try {
            val id = System.currentTimeMillis().toString() + "-" + file.name.hashCode()
            val dst = File(root, "$id.bin")
            file.copyTo(dst, overwrite = true)
            val meta = org.json.JSONObject().apply {
                put("id", id)
                put("original_path", file.absolutePath)
                put("name", file.name)
                put("size", file.length())
                put("date", SimpleDateFormat(
                    "yyyy-MM-dd HH:mm:ss", Locale.getDefault()).format(Date()))
            }
            File(metaDir, "$id.json").writeText(meta.toString())
            file.delete()
            true
        } catch (e: Exception) {
            false
        }
    }

    fun list(): List<org.json.JSONObject> {
        val out = mutableListOf<org.json.JSONObject>()
        metaDir.listFiles()?.filter { it.extension == "json" }?.forEach { f ->
            try {
                out.add(org.json.JSONObject(f.readText()))
            } catch (_: Exception) {
            }
        }
        return out.sortedByDescending { it.optString("date") }
    }

    fun restore(id: String): Boolean {
        return try {
            val meta = org.json.JSONObject(File(metaDir, "$id.json").readText())
            val src = File(root, "$id.bin")
            val dst = File(meta.getString("original_path"))
            dst.parentFile?.mkdirs()
            src.copyTo(dst, overwrite = true)
            src.delete()
            File(metaDir, "$id.json").delete()
            true
        } catch (e: Exception) {
            false
        }
    }

    fun remove(id: String): Boolean {
        File(root, "$id.bin").delete()
        File(metaDir, "$id.json").delete()
        return true
    }
}
