package com.admirepowered.pulse.core

object PulseCoreBridge {
    val isAvailable: Boolean = runCatching {
        System.loadLibrary("pulsecore")
    }.isSuccess

    private external fun nativeVersion(): String
    private external fun nativeStart(configPath: String, homeDir: String, tunFd: Int): Int
    private external fun nativeStop()
    private external fun nativeRunning(): Boolean
    private external fun nativeLastError(): String

    fun start(configPath: String, homeDir: String, tunFd: Int): Result<Unit> {
        if (!isAvailable) return Result.failure(IllegalStateException("Go mihomo core 未加载"))
        val code = nativeStart(configPath, homeDir, tunFd)
        return if (code == 0) {
            Result.success(Unit)
        } else {
            Result.failure(IllegalStateException(nativeLastError().ifBlank { "mihomo 启动失败: $code" }))
        }
    }

    fun stop() {
        if (isAvailable) nativeStop()
    }

    fun isRunning(): Boolean {
        return isAvailable && nativeRunning()
    }

    fun statusText(): String {
        return if (isAvailable) {
            "Go mihomo core 已加载: ${nativeVersion()}"
        } else {
            "Go mihomo core 未打包"
        }
    }
}
