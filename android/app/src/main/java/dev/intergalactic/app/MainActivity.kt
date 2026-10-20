package dev.intergalactic.app

import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.TextView
import androidx.appcompat.app.AppCompatActivity
import dev.intergalactic.core.MobileException
import dev.intergalactic.core.MobileNetwork
import dev.intergalactic.core.describeInvite
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class MainActivity : AppCompatActivity(), EngineHolder.Listener {
    private lateinit var nodeId: TextView
    private lateinit var toggle: Button
    private lateinit var invite: EditText
    private lateinit var join: Button
    private lateinit var message: TextView
    private lateinit var list: LinearLayout
    private val handler = Handler(Looper.getMainLooper())
    private val scope = CoroutineScope(Dispatchers.Main)
    private val refresh = object : Runnable {
        override fun run() {
            render()
            handler.postDelayed(this, 2000)
        }
    }

    private val vpnPermission = registerForActivityResult(androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == Activity.RESULT_OK) IgVpnService.start(this) else message.text = "VPN permission denied"
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        nodeId = findViewById(R.id.node_id)
        toggle = findViewById(R.id.toggle)
        invite = findViewById(R.id.invite)
        join = findViewById(R.id.join)
        message = findViewById(R.id.message)
        list = findViewById(R.id.list)

        val engine = EngineHolder.ensureStarted(this)
        nodeId.text = "node ${engine.nodeId()}"

        // Automation and deep links: `am start ... --es invite ig1:... --ez connect true`.
        intent?.getStringExtra(EXTRA_INVITE)?.let { inv ->
            invite.setText(inv)
            val connect = intent.getBooleanExtra(EXTRA_CONNECT, false)
            scope.launch {
                val result = withContext(Dispatchers.IO) { runCatching { engine.join(inv) } }
                result.onSuccess {
                    message.text = "joined ${it.name} as ${it.address}"
                    if (connect) startVpn()
                }.onFailure { message.text = it.message ?: "join failed" }
                render()
            }
        }

        toggle.setOnClickListener {
            if (IgVpnService.running) IgVpnService.stop(this) else startVpn()
            handler.postDelayed({ render() }, 300)
        }

        join.setOnClickListener {
            val text = invite.text.toString().trim()
            if (text.isEmpty()) return@setOnClickListener
            message.text = try { "joining ${describeInvite(text)}…" } catch (e: MobileException) { e.message }
            join.isEnabled = false
            scope.launch {
                val result = withContext(Dispatchers.IO) {
                    runCatching { EngineHolder.ensureStarted(this@MainActivity).join(text) }
                }
                join.isEnabled = true
                result.onSuccess {
                    invite.setText("")
                    message.text = "joined ${it.name} as ${it.address}"
                    render()
                }.onFailure { message.text = it.message ?: "join failed" }
            }
        }
    }

    private fun startVpn() {
        val prep: Intent? = VpnService.prepare(this)
        if (prep != null) vpnPermission.launch(prep) else IgVpnService.start(this)
    }

    companion object {
        const val EXTRA_INVITE = "invite"
        const val EXTRA_CONNECT = "connect"
    }

    override fun onStart() {
        super.onStart()
        EngineHolder.addListener(this)
        handler.post(refresh)
    }

    override fun onStop() {
        handler.removeCallbacks(refresh)
        EngineHolder.removeListener(this)
        super.onStop()
    }

    override fun onNetworksChanged(networks: List<MobileNetwork>) {
        handler.post { render() }
    }

    override fun onPeersChanged() {
        handler.post { render() }
    }

    private fun render() {
        val engine = EngineHolder.engine ?: return
        toggle.text = getString(if (IgVpnService.running) R.string.disconnect else R.string.connect)
        val status = runCatching { engine.status() }.getOrNull() ?: return
        list.removeAllViews()
        fun row(text: String, mono: Boolean = false, onLongClick: (() -> Unit)? = null) {
            val tv = TextView(this)
            tv.text = text
            tv.setPadding(0, 8, 0, 8)
            if (mono) tv.typeface = android.graphics.Typeface.MONOSPACE
            if (onLongClick != null) tv.setOnLongClickListener { onLongClick(); true }
            list.addView(tv)
        }
        row("NETWORKS", mono = true)
        if (status.networks.isEmpty()) row("none joined. Paste an invite above.")
        for (n in status.networks) {
            val lh = if (n.lighthouseConnected) "connected" else "disconnected"
            val v6 = n.address6?.let { "  $it/${n.prefixLen6}" } ?: ""
            row("${n.name}  ${n.address}/${n.prefixLen}$v6\n  ${n.dnsName}  ${n.policySummary}  relay:${n.relayLimit}  [$lh]  (long-press to leave)") {
                scope.launch(Dispatchers.IO) { runCatching { engine.leave(n.id) } }
            }
        }
        row("")
        row("PEERS", mono = true)
        if (status.peers.isEmpty()) row("no peers.")
        for (p in status.peers) {
            val hs = p.lastHandshakeSecsAgo?.let { "${it}s ago" } ?: "-"
            row("${p.hostname}  ${p.addresses.joinToString(" ")}\n  ${p.names.joinToString(" ")}\n  ${p.path}  ${p.endpoint ?: ""}  hs:$hs  ${if (p.online) "online" else "offline"}")
        }
        list.visibility = View.VISIBLE
    }
}
