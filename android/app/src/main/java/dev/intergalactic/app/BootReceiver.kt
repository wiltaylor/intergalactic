package dev.intergalactic.app

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.util.Log

/**
 * Brings the tunnel back after a reboot or an app update when it was on
 * before. Both broadcasts allow a foreground service start. The VPN consent
 * survives updates; if it was revoked, `prepare` is non-null and the user
 * reconnects from the app.
 */
class BootReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        if (intent.action != Intent.ACTION_BOOT_COMPLETED && intent.action != Intent.ACTION_MY_PACKAGE_REPLACED) return
        if (!IgVpnService.wanted(context)) return
        if (VpnService.prepare(context) != null) {
            Log.w("ig/vpn", "VPN consent missing after ${intent.action}; not restarting")
            return
        }
        Log.i("ig/vpn", "restoring the tunnel after ${intent.action}")
        IgVpnService.start(context)
    }
}
