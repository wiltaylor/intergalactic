package dev.intergalactic.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import dev.intergalactic.core.MobileNetwork

/**
 * Owns the single TUN interface Android allows per app. Every joined network's
 * address and route is added to it; the Rust engine demultiplexes by address.
 * When memberships change the interface is rebuilt and the new fd handed over.
 */
class IgVpnService : VpnService(), EngineHolder.Listener {
    companion object {
        const val ACTION_START = "dev.intergalactic.app.START"
        const val ACTION_STOP = "dev.intergalactic.app.STOP"
        private const val TAG = "ig/vpn"
        private const val CHANNEL = "tunnel"
        private const val NOTIFICATION_ID = 1

        @Volatile var running = false
            private set

        fun start(context: Context) {
            val i = Intent(context, IgVpnService::class.java).setAction(ACTION_START)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) context.startForegroundService(i) else context.startService(i)
        }

        fun stop(context: Context) {
            context.startService(Intent(context, IgVpnService::class.java).setAction(ACTION_STOP))
        }
    }

    private var tun: ParcelFileDescriptor? = null

    override fun onCreate() {
        super.onCreate()
        EngineHolder.protector = { fd -> protect(fd) }
        EngineHolder.addListener(this)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                teardown()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                startForeground(NOTIFICATION_ID, buildNotification())
                val engine = EngineHolder.ensureStarted(this)
                rebuild(engine.networks())
                running = true
                return START_STICKY
            }
        }
    }

    override fun onNetworksChanged(networks: List<MobileNetwork>) {
        if (running) rebuild(networks)
    }

    private fun rebuild(networks: List<MobileNetwork>) {
        val engine = EngineHolder.engine ?: return
        if (networks.isEmpty()) {
            Log.i(TAG, "no networks; tearing down interface")
            engine.detachTun()
            tun?.close()
            tun = null
            return
        }
        val builder = Builder()
            .setSession("Intergalactic")
            .setMtu(1380)
            .setBlocking(false)
        for (n in networks) {
            builder.addAddress(n.address, n.prefixLen.toInt())
            val (netAddr, prefix) = n.cidr.split('/')
            builder.addRoute(netAddr, prefix.toInt())
        }
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) builder.setMetered(false)
        val pfd = builder.establish()
        if (pfd == null) {
            Log.e(TAG, "establish() returned null; VPN permission missing?")
            return
        }
        // Detach the old interface after the new one exists so routes never vanish.
        engine.detachTun()
        tun?.close()
        tun = pfd
        engine.attachTun(pfd.fd)
        Log.i(TAG, "interface up with ${networks.size} network(s)")
    }

    private fun teardown() {
        running = false
        EngineHolder.engine?.detachTun()
        tun?.close()
        tun = null
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    override fun onDestroy() {
        teardown()
        EngineHolder.removeListener(this)
        EngineHolder.protector = null
        super.onDestroy()
    }

    override fun onRevoke() {
        teardown()
        stopSelf()
    }

    private fun buildNotification(): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, getString(R.string.notification_channel), NotificationManager.IMPORTANCE_LOW)
            )
        }
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val b = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) Notification.Builder(this, CHANNEL) else Notification.Builder(this)
        return b.setContentTitle(getString(R.string.notification_title))
            .setSmallIcon(R.drawable.ic_stat)
            .setContentIntent(open)
            .setOngoing(true)
            .build()
    }
}
