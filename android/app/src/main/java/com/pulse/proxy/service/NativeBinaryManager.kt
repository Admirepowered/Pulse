package com.pulse.proxy.service

import android.content.Context
import android.os.Build
import java.io.File

class NativeBinaryManager(private val context: Context) {

    fun prepareVlessProxy(): File? {
        val outputDir = File(context.filesDir, "bin")
        val outputFile = File(outputDir, "vless_proxy")
        val abi = Build.SUPPORTED_ABIS.firstOrNull().orEmpty()

        val nativeBinary = nativeBinaryCandidates()
            .firstOrNull { it.exists() && it.length() > 0 }

        if (nativeBinary != null) {
            nativeBinary.setExecutable(true)
            return nativeBinary
        }

        outputDir.mkdirs()
        val assetPaths = listOf(
            "$abi/vless_proxy",
            "jniLibs/$abi/vless_proxy",
            "bin/$abi/vless_proxy"
        )

        for (assetPath in assetPaths) {
            try {
                context.assets.open(assetPath).use { input ->
                    outputFile.outputStream().use { output ->
                        input.copyTo(output)
                    }
                }
                if (outputFile.exists() && outputFile.length() > 0) {
                    outputFile.setExecutable(true)
                    return outputFile
                }
            } catch (_: Exception) {
            }
        }

        return null
    }

    fun describeSearchPaths(): String {
        return (nativeBinaryCandidates() + File(File(context.filesDir, "bin"), "vless_proxy"))
            .joinToString(", ") { it.absolutePath }
    }

    private fun nativeBinaryCandidates(): List<File> {
        return listOf(
            File(context.applicationInfo.nativeLibraryDir, "libvless_proxy.so"),
            File(context.applicationInfo.dataDir, "lib/libvless_proxy.so")
        )
    }

    fun abi(): String = Build.SUPPORTED_ABIS.firstOrNull().orEmpty()
}
