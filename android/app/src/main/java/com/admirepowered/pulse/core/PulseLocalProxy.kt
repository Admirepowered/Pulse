package com.admirepowered.pulse.core

import android.content.Context
import java.io.File
import java.net.InetSocketAddress
import java.net.Proxy

object PulseLocalProxy {
    fun httpProxy(context: Context): Proxy {
        return Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", port(context)))
    }

    fun port(context: Context): Int {
        val content = runCatching { PulseProfileStore.active(context).path.let(::File).readText(Charsets.UTF_8) }
            .getOrDefault("")
        return mixedPortPattern.find(content)?.groupValues?.getOrNull(1)?.toIntOrNull()
            ?: portPattern.find(content)?.groupValues?.getOrNull(1)?.toIntOrNull()
            ?: 7890
    }

    private val mixedPortPattern = Regex("""(?m)^\s*mixed-port\s*:\s*(\d+)\s*$""")
    private val portPattern = Regex("""(?m)^\s*port\s*:\s*(\d+)\s*$""")
}
