package com.pulse.proxy.config

import android.content.Context
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

class MmdbManager(private val context: Context) {

    private val mmdbFile: File
        get() = File(context.filesDir, "Country.mmdb")

    private val mmdbUrl =
        "https://github.com/Dreamacro/maxmind-geoip/releases/latest/download/Country.mmdb"

    fun getMmdbPath(): String = mmdbFile.absolutePath

    fun isMmdbAvailable(): Boolean = mmdbFile.exists() && mmdbFile.length() > 1024 * 1024

    suspend fun ensureMmdbAvailable(): Boolean = withContext(Dispatchers.IO) {
        if (isMmdbAvailable()) return@withContext true

        try {
            context.assets.open("Country.mmdb").use { input ->
                mmdbFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
            if (isMmdbAvailable()) return@withContext true
        } catch (_: Exception) {}

        downloadMmdb()
    }

    private fun downloadMmdb(): Boolean {
        try {
            val url = URL(mmdbUrl)
            val redirects = 0
            var currentUrl = url
            var conn: HttpURLConnection? = null

            // Follow redirects to get the actual download URL
            for (i in 0..4) {
                conn = currentUrl.openConnection() as HttpURLConnection
                conn.instanceFollowRedirects = false
                conn.connectTimeout = 15000
                conn.readTimeout = 30000
                conn.connect()

                val code = conn.responseCode
                if (code in 300..399) {
                    val location = conn.getHeaderField("Location") ?: break
                    currentUrl = URL(location)
                    conn.disconnect()
                } else {
                    break
                }
            }

            if (conn?.responseCode != 200) {
                conn?.disconnect()
                return false
            }

            conn.inputStream.use { input ->
                mmdbFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
            conn.disconnect()

            return isMmdbAvailable()
        } catch (_: Exception) {
            return false
        }
    }
}
