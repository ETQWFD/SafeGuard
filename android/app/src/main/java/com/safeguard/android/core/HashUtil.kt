package com.safeguard.android.core

import java.security.MessageDigest

object HashUtil {

    /** 计算文件 SHA-256（真实哈希，分块读取支持大文件） */
    fun fileSha256(file: java.io.File): String {
        val md = MessageDigest.getInstance("SHA-256")
        file.inputStream().use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n <= 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest().toHex()
    }

    /** 计算文件 MD5 */
    fun fileMd5(file: java.io.File): String {
        val md = MessageDigest.getInstance("MD5")
        file.inputStream().use { input ->
            val buf = ByteArray(64 * 1024)
            while (true) {
                val n = input.read(buf)
                if (n <= 0) break
                md.update(buf, 0, n)
            }
        }
        return md.digest().toHex()
    }

    fun ByteArray.toHex(): String =
        joinToString("") { "%02x".format(it) }
}
