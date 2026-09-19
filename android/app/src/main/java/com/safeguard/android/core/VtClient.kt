package com.safeguard.android.core

import android.content.Context
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

data class VtResult(
    val malicious: Long = 0,
    val suspicious: Long = 0,
    val harmless: Long = 0,
    val found: Boolean = false,
    val error: String = "",
)

/** VirusTotal v3 API 客户端（OkHttp），Key 存于 SharedPreferences */
class VtClient(private val context: Context) {

    private val prefs =
        context.getSharedPreferences("safeguard", Context.MODE_PRIVATE)
    private val client = OkHttpClient.Builder()
        .connectTimeout(20, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .build()

    fun hasKey(): Boolean = apiKey().isNotEmpty()

    fun apiKey(): String = prefs.getString("vt_api_key", "") ?: ""

    fun setApiKey(key: String) {
        prefs.edit().putString("vt_api_key", key.trim()).apply()
    }

    fun query(hash: String): VtResult {
        val key = apiKey()
        if (key.isEmpty()) return VtResult(error = "no_api_key")
        val req = Request.Builder()
            .url("https://www.virustotal.com/api/v3/files/${hash.trim().lowercase()}")
            .header("x-apikey", key)
            .header("Accept", "application/json")
            .build()
        return try {
            client.newCall(req).execute().use { resp ->
                when (resp.code) {
                    404 -> VtResult(found = false)
                    401, 403 -> VtResult(error = "api_key_invalid")
                    else -> {
                        val body = resp.body?.string() ?: "{}"
                        val root = JSONObject(body)
                        val data = root.optJSONObject("data")
                        if (data == null) VtResult(error = "not_found")
                        else {
                            val stats = data.optJSONObject("attributes")
                                ?.optJSONObject("last_analysis_stats")
                            VtResult(
                                malicious = stats?.optLong("malicious", 0) ?: 0,
                                suspicious = stats?.optLong("suspicious", 0) ?: 0,
                                harmless = stats?.optLong("harmless", 0) ?: 0,
                                found = true,
                            )
                        }
                    }
                }
            }
        } catch (e: Exception) {
            VtResult(error = e.message ?: "network_error")
        }
    }
}
