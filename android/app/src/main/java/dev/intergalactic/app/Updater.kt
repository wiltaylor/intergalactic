package dev.intergalactic.app

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.Build
import android.provider.Settings
import android.util.Log
import androidx.core.content.FileProvider
import org.json.JSONArray
import java.io.File
import java.net.HttpURLConnection
import java.net.URL

/**
 * In-app updates from the project's GitHub Releases.
 *
 * Every release carries `intergalactic-<version>.apk`, signed with the project's
 * release key (CI signs it from repository secrets). [check] finds the newest
 * release with an APK that outranks the running version, [download] fetches it
 * over the phone's normal connection (public addresses never enter the tunnel)
 * and [install] hands it to the Android package installer, which verifies the
 * signature against the installed app before it replaces it.
 */
object Updater {
    private const val TAG = "ig/update"
    private const val PREFS = "updater"
    private const val KEY_LAST_CHECK = "last_check"
    private const val CHECK_INTERVAL_MS = 6 * 60 * 60 * 1000L

    data class Release(
        val version: String,
        val apkUrl: String,
        val apkName: String,
        val size: Long,
        val pageUrl: String,
        val prerelease: Boolean,
    )

    /** Semantic version: `M.m.p` with an optional `-tag`. */
    private data class Ver(val nums: List<Int>, val tag: String?) : Comparable<Ver> {
        override fun compareTo(other: Ver): Int {
            for (i in 0 until 3) {
                val c = nums[i].compareTo(other.nums[i])
                if (c != 0) return c
            }
            // Same numbers: a release beats a pre-release; "dev" is below everything.
            return rank(tag).compareTo(rank(other.tag)).let { if (it != 0) it else (tag ?: "").compareTo(other.tag ?: "") }
        }

        private fun rank(t: String?): Int = when {
            t == null -> 2
            t == "dev" -> 0
            else -> 1
        }

        companion object {
            fun parse(s: String): Ver? {
                val v = s.trim().removePrefix("v")
                val core = v.substringBefore('-')
                val tag = if (v.contains('-')) v.substringAfter('-') else null
                val nums = core.split('.').map { it.toIntOrNull() ?: return null }
                if (nums.size != 3) return null
                return Ver(nums, tag)
            }
        }
    }

    /** True when `candidate` is a newer version than `current`. */
    fun isNewer(candidate: String, current: String): Boolean {
        val c = Ver.parse(candidate) ?: return false
        val cur = Ver.parse(current) ?: return true
        return c > cur
    }

    fun dueForCheck(context: Context): Boolean {
        val last = context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).getLong(KEY_LAST_CHECK, 0)
        return System.currentTimeMillis() - last > CHECK_INTERVAL_MS
    }

    /**
     * Newest release with an APK that outranks the running version, or null.
     * Blocking; call off the main thread. Pre-releases count when the running
     * build is a pre-release or a dev build, or when [includePrerelease] is set.
     */
    fun check(context: Context, includePrerelease: Boolean = true): Release? {
        context.getSharedPreferences(PREFS, Context.MODE_PRIVATE).edit().putLong(KEY_LAST_CHECK, System.currentTimeMillis()).apply()
        val current = BuildConfig.VERSION_NAME
        val wantPre = includePrerelease || current.contains('-')
        val url = URL("https://api.github.com/repos/${BuildConfig.GITHUB_REPO}/releases?per_page=20")
        val conn = url.openConnection() as HttpURLConnection
        conn.connectTimeout = 10_000
        conn.readTimeout = 15_000
        conn.setRequestProperty("Accept", "application/vnd.github+json")
        conn.setRequestProperty("User-Agent", "intergalactic-android/$current")
        val body = try {
            if (conn.responseCode != 200) {
                Log.w(TAG, "release list: HTTP ${conn.responseCode}")
                return null
            }
            conn.inputStream.bufferedReader().readText()
        } finally {
            conn.disconnect()
        }
        var best: Release? = null
        val releases = JSONArray(body)
        for (i in 0 until releases.length()) {
            val r = releases.getJSONObject(i)
            if (r.optBoolean("draft")) continue
            val pre = r.optBoolean("prerelease")
            if (pre && !wantPre) continue
            val version = r.optString("tag_name").removePrefix("v")
            if (!isNewer(version, current)) continue
            val assets = r.optJSONArray("assets") ?: continue
            for (j in 0 until assets.length()) {
                val a = assets.getJSONObject(j)
                val name = a.optString("name")
                if (!name.endsWith(".apk")) continue
                val candidate = Release(
                    version = version,
                    apkUrl = a.optString("browser_download_url"),
                    apkName = name,
                    size = a.optLong("size"),
                    pageUrl = r.optString("html_url"),
                    prerelease = pre,
                )
                if (best == null || isNewer(candidate.version, best.version)) best = candidate
            }
        }
        return best
    }

    /** Download the APK into the app's cache. Blocking; reports bytes so far. */
    fun download(context: Context, release: Release, onProgress: (Long, Long) -> Unit): File {
        val dir = File(context.cacheDir, "updates").apply { mkdirs() }
        dir.listFiles()?.forEach { if (it.name != release.apkName) it.delete() }
        val file = File(dir, release.apkName)
        val conn = URL(release.apkUrl).openConnection() as HttpURLConnection
        conn.connectTimeout = 10_000
        conn.readTimeout = 30_000
        conn.instanceFollowRedirects = true
        conn.setRequestProperty("User-Agent", "intergalactic-android/${BuildConfig.VERSION_NAME}")
        try {
            if (conn.responseCode != 200) throw IllegalStateException("download: HTTP ${conn.responseCode}")
            val total = if (conn.contentLengthLong > 0) conn.contentLengthLong else release.size
            conn.inputStream.use { input ->
                file.outputStream().use { out ->
                    val buf = ByteArray(64 * 1024)
                    var done = 0L
                    while (true) {
                        val n = input.read(buf)
                        if (n < 0) break
                        out.write(buf, 0, n)
                        done += n
                        onProgress(done, total)
                    }
                }
            }
        } finally {
            conn.disconnect()
        }
        return file
    }

    /**
     * Hand the APK to the package installer. Returns false when the user must
     * first allow this app to install updates; the settings page is opened then.
     */
    fun install(context: Context, file: File): Boolean {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && !context.packageManager.canRequestPackageInstalls()) {
            context.startActivity(
                Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:${context.packageName}"))
                    .addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            )
            return false
        }
        val uri = FileProvider.getUriForFile(context, "${context.packageName}.fileprovider", file)
        context.startActivity(
            Intent(Intent.ACTION_VIEW)
                .setDataAndType(uri, "application/vnd.android.package-archive")
                .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION or Intent.FLAG_ACTIVITY_NEW_TASK)
        )
        return true
    }
}
