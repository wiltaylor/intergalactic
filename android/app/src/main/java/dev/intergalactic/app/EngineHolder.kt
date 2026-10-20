package dev.intergalactic.app

import android.content.Context
import android.os.Build
import android.util.Log
import dev.intergalactic.core.MobileCallbacks
import dev.intergalactic.core.MobileEngine
import dev.intergalactic.core.MobileNetwork
import dev.intergalactic.core.generateState
import java.io.File
import java.util.concurrent.CopyOnWriteArrayList

/**
 * Process-wide owner of the Rust engine. The engine runs whether or not the
 * VPN interface is up: it keeps lighthouse sessions alive so joins and status
 * work from the UI, and traffic flows once [IgVpnService] attaches a TUN.
 */
object EngineHolder : MobileCallbacks {
    private const val TAG = "ig/engine"

    interface Listener {
        fun onNetworksChanged(networks: List<MobileNetwork>) {}
        fun onPeersChanged() {}
    }

    @Volatile var engine: MobileEngine? = null
        private set
    private lateinit var stateFile: File
    private val listeners = CopyOnWriteArrayList<Listener>()

    /** Set by the VPN service while it is alive, so sockets can be protected. */
    @Volatile var protector: ((Int) -> Boolean)? = null

    @Synchronized
    fun ensureStarted(context: Context): MobileEngine {
        engine?.let { return it }
        stateFile = File(context.filesDir, "state.json")
        val state = if (stateFile.exists()) stateFile.readText() else generateState().also { stateFile.writeText(it) }
        val hostname = (Build.MODEL ?: "android").replace(' ', '-')
        val e = MobileEngine(state, hostname, this)
        engine = e
        Log.i(TAG, "engine started, node ${e.nodeId()}")
        return e
    }

    fun addListener(l: Listener) = listeners.add(l)
    fun removeListener(l: Listener) = listeners.remove(l)

    // ---- MobileCallbacks (called from Rust threads) ----

    override fun protectSocket(fd: Int) {
        val p = protector
        if (p == null) {
            Log.d(TAG, "no VPN service yet; socket $fd left unprotected (overlay routes only, so this is safe)")
        } else if (!p(fd)) {
            Log.w(TAG, "protect($fd) failed")
        }
    }

    override fun onNetworksChanged(networks: List<MobileNetwork>, stateJson: String) {
        try {
            stateFile.writeText(stateJson)
        } catch (e: Exception) {
            Log.e(TAG, "failed to persist state", e)
        }
        listeners.forEach { it.onNetworksChanged(networks) }
    }

    override fun onPeersChanged() {
        listeners.forEach { it.onPeersChanged() }
    }

    override fun onLighthouseStatus(lighthouse: String, connected: Boolean) {
        Log.i(TAG, "lighthouse $lighthouse connected=$connected")
    }
}
