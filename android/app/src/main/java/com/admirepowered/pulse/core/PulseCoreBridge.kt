package com.admirepowered.pulse.core

object PulseCoreBridge {
    val isAvailable: Boolean = runCatching {
        System.loadLibrary("pulsecore")
    }.isSuccess

    fun statusText(): String {
        return if (isAvailable) {
            "Go mihomo core 已加载"
        } else {
            "Go mihomo core 未打包"
        }
    }
}
