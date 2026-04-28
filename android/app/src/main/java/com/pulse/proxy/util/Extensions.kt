package com.pulse.proxy.util

import java.io.Closeable
import java.net.InetAddress

fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

fun InetAddress.toByteString(): String = address.joinToString(".") { (it.toInt() and 0xFF).toString() }

inline fun <T : Closeable, R> T.useSafely(block: (T) -> R): R? {
    return try {
        block(this)
    } catch (_: Exception) {
        null
    } finally {
        try { close() } catch (_: Exception) {}
    }
}
