package com.safeguard.android.core

import android.content.Context
import java.io.File

/**
 * 白名单：系统目录前缀内置放行 + 用户自定义目录（SharedPreferences 持久化）。
 */
class Whitelist(private val context: Context) {

    private val prefs =
        context.getSharedPreferences("safeguard", Context.MODE_PRIVATE)

    private val systemPrefixes = listOf(
        "/system", "/vendor", "/product", "/apex",
        "/data/system", "/data/dalvik-cache", "/proc", "/sys",
    )

    fun customPaths(): List<String> =
        prefs.getStringSet("whitelist", emptySet())?.toList() ?: emptyList()

    fun add(path: String) {
        val set = prefs.getStringSet("whitelist", emptySet())!!.toMutableSet()
        set.add(path)
        prefs.edit().putStringSet("whitelist", set).apply()
    }

    fun remove(path: String) {
        val set = prefs.getStringSet("whitelist", emptySet())!!.toMutableSet()
        set.remove(path)
        prefs.edit().putStringSet("whitelist", set).apply()
    }

    fun isWhitelisted(path: String): Boolean {
        val lower = path.lowercase()
        if (systemPrefixes.any { lower.startsWith(it) }) return true
        return customPaths().any { lower.startsWith(it.lowercase()) }
    }
}
