package com.pulse.proxy.service

import android.content.Context
import com.pulse.proxy.util.LogBuffer
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import java.io.BufferedReader
import java.io.File
import java.io.InputStreamReader

class ProxyProcessManager(
    private val context: Context,
    private val logBuffer: LogBuffer
) {
    private val scope = CoroutineScope(Dispatchers.IO + Job())
    private var process: Process? = null
    private var monitorJob: Job? = null

    @Volatile var isRunning = false
        private set

    fun start(configPath: String): Boolean {
        if (isRunning) return true

        return try {
            val binaryManager = NativeBinaryManager(context)
            val binFile = binaryManager.prepareVlessProxy()
            if (binFile == null) {
                logBuffer.append("Native binary not found for ABI ${binaryManager.abi()}. Reinstall the latest APK. Tried: ${binaryManager.describeSearchPaths()}")
                return false
            }
            binFile.setExecutable(true)

            val pb = ProcessBuilder(
                binFile.absolutePath, "run", configPath
            )
            pb.directory(context.filesDir)
            pb.redirectErrorStream(true)
            pb.environment()["HOME"] = context.filesDir.absolutePath

            process = pb.start()
            isRunning = true

            // Monitor stdout
            monitorJob = scope.launch {
                val reader = BufferedReader(InputStreamReader(process!!.inputStream))
                while (isActive && isRunning) {
                    val line = reader.readLine() ?: break
                    logBuffer.append(line)
                }
            }

            // Wait for process exit
            scope.launch {
                process?.waitFor()
                isRunning = false
                logBuffer.append("Proxy process exited")
            }

            logBuffer.append("Proxy started on 127.0.0.1:1080")
            true
        } catch (e: Exception) {
            logBuffer.append("Failed to start proxy: ${e.message}")
            isRunning = false
            false
        }
    }

    fun stop() {
        isRunning = false
        monitorJob?.cancel()
        try {
            process?.destroy()
            process?.waitFor()
        } catch (_: Exception) {}
        process = null
    }
}
