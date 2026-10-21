package dev.intergalactic.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.LinkProperties
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.util.Log
import dev.intergalactic.core.MobileNetwork

/**
 * Owns the single TUN interface Android allows per app. Every joined network's
 * address and route is added to it; the Rust engine demultiplexes by address.
 * When memberships change the interface is rebuilt and the new fd handed over.
 *
 * DNS: Android has no split DNS, so every query from every app goes to the
 * in-tunnel responders we add with `addDnsServer`. The engine answers overlay
 * names itself and forwards the rest to the underlying network's resolvers,
 * which this service reads from the non-VPN networks' [LinkProperties] and
 * pushes with `setUpstreamDns` on every change. The forwarding sockets are
 * protected like the engine's other sockets, so they bypass the tunnel.
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

    /** Non-VPN networks with internet access and their current link properties. */
    private val underlying = LinkedHashMap<Network, LinkProperties>()
    private var connectivity: ConnectivityManager? = null
    private val networkCallback = object : ConnectivityManager.NetworkCallback() {
        override fun onAvailable(network: Network) {
            connectivity?.getLinkProperties(network)?.let { synchronized(underlying) { underlying[network] = it } }
            pushUpstreamDns()
            EngineHolder.engine?.networkChanged()
        }

        override fun onLinkPropertiesChanged(network: Network, lp: LinkProperties) {
            synchronized(underlying) { underlying[network] = lp }
            pushUpstreamDns()
        }

        override fun onLost(network: Network) {
            synchronized(underlying) { underlying.remove(network) }
            pushUpstreamDns()
            EngineHolder.engine?.networkChanged()
        }
    }

    override fun onCreate() {
        super.onCreate()
        EngineHolder.protector = { fd -> protect(fd) }
        EngineHolder.addListener(this)
        val cm = getSystemService(ConnectivityManager::class.java)
        connectivity = cm
        // NOT_VPN keeps our own tunnel out of the list, or we would forward
        // queries to ourselves.
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .addCapability(NetworkCapabilities.NET_CAPABILITY_NOT_VPN)
            .build()
        try {
            cm.registerNetworkCallback(request, networkCallback)
        } catch (e: Exception) {
            Log.w(TAG, "network callback registration failed; upstream DNS will not update", e)
        }
    }

    /**
     * Hand the underlying networks' resolvers to the engine. Wi-Fi and Ethernet
     * come first: the protected sockets use the system default network, which
     * prefers those, and the engine tries the servers in order.
     */
    private fun pushUpstreamDns() {
        val engine = EngineHolder.engine ?: return
        val cm = connectivity ?: return
        val snapshot = synchronized(underlying) { underlying.entries.map { it.key to it.value } }
        val ordered = snapshot.sortedBy { (network, _) ->
            val caps = cm.getNetworkCapabilities(network)
            when {
                caps == null -> 2
                caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                    caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> 0
                else -> 1
            }
        }
        val servers = ordered
            .flatMap { (_, lp) -> lp.dnsServers }
            // Link-local resolvers need an interface scope the engine cannot supply.
            .filter { !it.isLinkLocalAddress }
            .mapNotNull { it.hostAddress?.substringBefore('%') }
            .distinct()
        Log.i(TAG, "upstream dns: $servers")
        engine.setUpstreamDns(servers)
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_STOP -> {
                teardown()
                stopSelf()
                return START_NOT_STICKY
            }
            else -> {
                startForeground(NOTIFICATION_ID, buildNotification(statusText()))
                val engine = EngineHolder.ensureStarted(this)
                rebuild(engine.networks())
                running = true
                return START_STICKY
            }
        }
    }

    override fun onNetworksChanged(networks: List<MobileNetwork>) {
        if (running) {
            rebuild(networks)
            updateNotification()
        }
    }

    override fun onPeersChanged() {
        if (running) updateNotification()
    }

    private var lastNotificationText: String? = null

    /** Keep the status-bar entry current: networks and peers online. */
    private fun updateNotification() {
        val text = statusText()
        if (text == lastNotificationText) return
        lastNotificationText = text
        getSystemService(NotificationManager::class.java).notify(NOTIFICATION_ID, buildNotification(text))
    }

    private fun statusText(): String {
        val status = runCatching { EngineHolder.engine?.status() }.getOrNull() ?: return getString(R.string.notification_no_networks)
        if (status.networks.isEmpty()) return getString(R.string.notification_no_networks)
        val nets = status.networks.joinToString(", ") { it.name }
        val online = status.peers.count { it.online }
        return "$nets · " + getString(R.string.peers_online, online, status.peers.size)
    }

    /** What the current interface was built from; a push that changes nothing here keeps it. */
    private var tunConfig: String? = null

    private fun rebuild(networks: List<MobileNetwork>) {
        val engine = EngineHolder.engine ?: return
        if (networks.isEmpty()) {
            Log.i(TAG, "no networks; tearing down interface")
            engine.detachTun()
            tun?.close()
            tun = null
            tunConfig = null
            return
        }
        // Peer lists and lighthouse states change often; only addresses, routes
        // and DNS settings need a new interface. Re-establishing for anything
        // else would drop every socket on the tunnel.
        val config = networks.joinToString("|") { n ->
            listOf(n.address, n.prefixLen, n.cidr, n.dnsServer, n.dnsSearchDomain,
                n.address6, n.cidr6, n.prefixLen6, n.dnsServer6).joinToString(",")
        }
        if (tun != null && config == tunConfig) {
            pushUpstreamDns()
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
            // Every query goes to these in-tunnel responders; the engine answers
            // overlay names and forwards the rest (see pushUpstreamDns).
            builder.addDnsServer(n.dnsServer)
            builder.addSearchDomain(n.dnsSearchDomain)
            val a6 = n.address6
            val c6 = n.cidr6
            val p6 = n.prefixLen6
            if (a6 != null && c6 != null && p6 != null) {
                builder.addAddress(a6, p6.toInt())
                val (net6, prefix6) = c6.split('/')
                builder.addRoute(net6, prefix6.toInt())
                n.dnsServer6?.let { builder.addDnsServer(it) }
            }
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
        tunConfig = config
        engine.attachTun(pfd.fd)
        // The callback may have fired before the engine existed: push now.
        pushUpstreamDns()
        Log.i(TAG, "interface up with ${networks.size} network(s)")
    }

    private fun teardown() {
        running = false
        EngineHolder.engine?.detachTun()
        tun?.close()
        tun = null
        tunConfig = null
        stopForeground(STOP_FOREGROUND_REMOVE)
    }

    override fun onDestroy() {
        teardown()
        try {
            connectivity?.unregisterNetworkCallback(networkCallback)
        } catch (e: Exception) {
            Log.d(TAG, "network callback already unregistered", e)
        }
        EngineHolder.engine?.setUpstreamDns(emptyList())
        EngineHolder.removeListener(this)
        EngineHolder.protector = null
        super.onDestroy()
    }

    override fun onRevoke() {
        teardown()
        stopSelf()
    }

    private fun buildNotification(text: String): Notification {
        val nm = getSystemService(NotificationManager::class.java)
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            nm.createNotificationChannel(
                NotificationChannel(CHANNEL, getString(R.string.notification_channel), NotificationManager.IMPORTANCE_LOW)
            )
        }
        val open = PendingIntent.getActivity(
            this, 0, Intent(this, MainActivity::class.java), PendingIntent.FLAG_IMMUTABLE
        )
        val stop = PendingIntent.getService(
            this, 1, Intent(this, IgVpnService::class.java).setAction(ACTION_STOP), PendingIntent.FLAG_IMMUTABLE
        )
        val b = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) Notification.Builder(this, CHANNEL) else Notification.Builder(this)
        val disconnect = Notification.Action.Builder(null, getString(R.string.disconnect), stop).build()
        return b.setContentTitle(getString(R.string.notification_title))
            .setContentText(text)
            .setSmallIcon(R.drawable.ic_stat)
            .setContentIntent(open)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .addAction(disconnect)
            .build()
    }
}
