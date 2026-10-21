package dev.intergalactic.app

import android.Manifest
import android.app.Activity
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.LayoutInflater
import android.view.Menu
import android.view.MenuItem
import android.view.View
import android.widget.ImageButton
import android.widget.LinearLayout
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.lifecycle.lifecycleScope
import com.google.android.material.appbar.MaterialToolbar
import com.google.android.material.card.MaterialCardView
import com.google.android.material.button.MaterialButton
import com.google.android.material.dialog.MaterialAlertDialogBuilder
import com.google.android.material.floatingactionbutton.ExtendedFloatingActionButton
import com.google.android.material.materialswitch.MaterialSwitch
import com.google.android.material.textfield.TextInputEditText
import com.google.android.material.textfield.TextInputLayout
import com.journeyapps.barcodescanner.ScanContract
import com.journeyapps.barcodescanner.ScanOptions
import dev.intergalactic.core.MobileException
import dev.intergalactic.core.MobileNetwork
import dev.intergalactic.core.MobilePeer
import dev.intergalactic.core.MobileStatus
import dev.intergalactic.core.describeInvite
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * One screen: a tunnel switch with its state, the joined networks, the peers,
 * and a button to join a network by scanning an invite QR code or pasting one.
 */
class MainActivity : AppCompatActivity(), EngineHolder.Listener {
    private lateinit var toggle: MaterialSwitch
    private lateinit var statusDot: View
    private lateinit var statusTitle: TextView
    private lateinit var statusDetail: TextView
    private lateinit var nodeId: TextView
    private lateinit var message: TextView
    private lateinit var networks: LinearLayout
    private lateinit var peers: LinearLayout
    private lateinit var join: ExtendedFloatingActionButton
    private lateinit var updateCard: MaterialCardView
    private lateinit var updateTitle: TextView
    private lateinit var updateDetail: TextView
    private lateinit var updateInstall: MaterialButton
    private lateinit var updateLater: MaterialButton
    private var pendingUpdate: Updater.Release? = null
    private var downloading = false

    private val handler = Handler(Looper.getMainLooper())
    // Coroutines end with the activity, so a result never reaches a destroyed instance.
    private val scope get() = lifecycleScope
    private val refresh = object : Runnable {
        override fun run() {
            render()
            handler.postDelayed(this, 2000)
        }
    }

    /** Invite field of the join dialog while it is open, so a scan can fill it. */
    private var pendingInviteField: TextInputEditText? = null

    private val vpnPermission = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == Activity.RESULT_OK) IgVpnService.start(this) else {
            showMessage("VPN permission denied")
            toggle.isChecked = false
        }
    }

    private val notificationPermission = registerForActivityResult(ActivityResultContracts.RequestPermission()) {
        // Either way the tunnel can start; without the permission the status entry is hidden.
        launchVpn()
    }

    private val scanner = registerForActivityResult(ScanContract()) { result ->
        val text = result.contents?.trim()
        if (text.isNullOrEmpty()) return@registerForActivityResult
        val field = pendingInviteField
        if (field != null) field.setText(text) else joinInvite(text, connect = true)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)
        setSupportActionBar(findViewById<MaterialToolbar>(R.id.toolbar))
        toggle = findViewById(R.id.toggle)
        statusDot = findViewById(R.id.status_dot)
        statusTitle = findViewById(R.id.status_title)
        statusDetail = findViewById(R.id.status_detail)
        nodeId = findViewById(R.id.node_id)
        message = findViewById(R.id.message)
        networks = findViewById(R.id.networks)
        peers = findViewById(R.id.peers)
        join = findViewById(R.id.join)
        updateCard = findViewById(R.id.update_card)
        updateTitle = findViewById(R.id.update_title)
        updateDetail = findViewById(R.id.update_detail)
        updateInstall = findViewById(R.id.update_install)
        updateLater = findViewById(R.id.update_later)
        supportActionBar?.subtitle = "v${BuildConfig.VERSION_NAME}"

        val engine = EngineHolder.ensureStarted(this)
        nodeId.text = "node ${engine.nodeId()}"
        updateInstall.setOnClickListener { installUpdate() }
        updateLater.setOnClickListener { updateCard.visibility = View.GONE }

        toggle.setOnClickListener {
            if (toggle.isChecked) startVpn() else IgVpnService.stop(this)
            handler.postDelayed({ render() }, 400)
        }
        join.setOnClickListener { showJoinDialog() }

        handleIntent(intent)
    }

    override fun onCreateOptionsMenu(menu: Menu): Boolean {
        menuInflater.inflate(R.menu.main, menu)
        return true
    }

    override fun onOptionsItemSelected(item: MenuItem): Boolean {
        if (item.itemId == R.id.check_updates) {
            checkForUpdates(manual = true)
            return true
        }
        return super.onOptionsItemSelected(item)
    }

    // ---- updates ----------------------------------------------------------------

    private fun checkForUpdates(manual: Boolean) {
        scope.launch {
            val result = withContext(Dispatchers.IO) { runCatching { Updater.check(this@MainActivity) } }
            result.onSuccess { release ->
                if (release != null) showUpdate(release)
                else if (manual) showMessage(getString(R.string.update_none, BuildConfig.VERSION_NAME), error = false)
            }.onFailure {
                if (manual) showMessage(getString(R.string.update_failed, it.message ?: it.javaClass.simpleName))
            }
        }
    }

    private fun showUpdate(release: Updater.Release) {
        pendingUpdate = release
        updateTitle.text = getString(R.string.update_available, release.version)
        updateDetail.text = getString(R.string.update_detail, BuildConfig.VERSION_NAME)
        updateInstall.isEnabled = true
        updateCard.visibility = View.VISIBLE
    }

    private fun installUpdate() {
        val release = pendingUpdate ?: return
        if (downloading) return
        downloading = true
        updateInstall.isEnabled = false
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching {
                    Updater.download(this@MainActivity, release) { done, total ->
                        val pct = if (total > 0) (done * 100 / total).toInt() else 0
                        handler.post { updateDetail.text = getString(R.string.update_downloading, "$pct%") }
                    }
                }
            }
            downloading = false
            result.onSuccess { file ->
                updateInstall.isEnabled = true
                // Queued behind the last progress post, so it is not overwritten.
                handler.post { updateDetail.text = getString(R.string.update_detail, BuildConfig.VERSION_NAME) }
                if (!Updater.install(this@MainActivity, file)) showMessage(getString(R.string.update_allow))
            }.onFailure {
                updateInstall.isEnabled = true
                showMessage(it.message ?: "download failed")
            }
        }
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        handleIntent(intent)
    }

    /** Automation and deep links: `am start ... --es invite ig1:... --ez connect true`. */
    private fun handleIntent(intent: Intent?) {
        val inv = intent?.getStringExtra(EXTRA_INVITE) ?: return
        intent.removeExtra(EXTRA_INVITE)
        joinInvite(inv, connect = intent.getBooleanExtra(EXTRA_CONNECT, false))
    }

    // ---- joining ----------------------------------------------------------------

    private fun showJoinDialog() {
        val view = LayoutInflater.from(this).inflate(R.layout.dialog_join, null)
        val field = view.findViewById<TextInputEditText>(R.id.invite)
        val layout = field.parent.parent as TextInputLayout
        val preview = view.findViewById<TextView>(R.id.preview)
        val scan = view.findViewById<MaterialButton>(R.id.scan)
        pendingInviteField = field
        layout.setEndIconOnClickListener {
            val clip = getSystemService(Context.CLIPBOARD_SERVICE) as ClipboardManager
            clip.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString()?.trim()?.let { field.setText(it) }
        }
        field.addTextChangedListener(object : android.text.TextWatcher {
            override fun afterTextChanged(s: android.text.Editable?) {
                val text = s?.toString()?.trim().orEmpty()
                preview.text = if (text.isEmpty()) "" else try { describeInvite(text) } catch (e: MobileException) { e.message ?: "not an invite" }
            }
            override fun beforeTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
            override fun onTextChanged(s: CharSequence?, a: Int, b: Int, c: Int) {}
        })
        val dialog = MaterialAlertDialogBuilder(this)
            .setTitle(R.string.join_network)
            .setView(view)
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.join) { _, _ ->
                val text = field.text?.toString()?.trim().orEmpty()
                if (text.isNotEmpty()) joinInvite(text, connect = true)
            }
            .setOnDismissListener { pendingInviteField = null }
            .create()
        scan.setOnClickListener {
            dialog.dismiss()
            pendingInviteField = null
            startScan()
        }
        dialog.show()
    }

    private fun startScan() {
        val options = ScanOptions()
            .setDesiredBarcodeFormats(ScanOptions.QR_CODE)
            .setPrompt(getString(R.string.scan_prompt))
            .setBeepEnabled(false)
            .setOrientationLocked(false)
        scanner.launch(options)
    }

    private fun joinInvite(text: String, connect: Boolean) {
        showMessage(try { "joining ${describeInvite(text)}…" } catch (e: MobileException) { e.message ?: "not an invite" })
        join.isEnabled = false
        scope.launch {
            val result = withContext(Dispatchers.IO) {
                runCatching { EngineHolder.ensureStarted(this@MainActivity).join(text) }
            }
            join.isEnabled = true
            result.onSuccess {
                showMessage("joined ${it.name} as ${it.address}", error = false)
                if (connect && !IgVpnService.running) startVpn()
                render()
            }.onFailure { showMessage(it.message ?: "join failed") }
        }
    }

    private fun confirmLeave(n: MobileNetwork) {
        MaterialAlertDialogBuilder(this)
            .setTitle(getString(R.string.leave_network, n.name))
            .setMessage(getString(R.string.leave_network_detail, n.name))
            .setNegativeButton(R.string.cancel, null)
            .setPositiveButton(R.string.leave) { _, _ ->
                scope.launch {
                    val r = withContext(Dispatchers.IO) { runCatching { EngineHolder.engine?.leave(n.id) } }
                    r.onFailure { showMessage(it.message ?: "leave failed") }
                    render()
                }
            }
            .show()
    }

    // ---- tunnel -----------------------------------------------------------------

    private fun startVpn() {
        if (isFinishing || isDestroyed) return
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU &&
            ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) != PackageManager.PERMISSION_GRANTED
        ) {
            notificationPermission.launch(Manifest.permission.POST_NOTIFICATIONS)
            return
        }
        launchVpn()
    }

    private fun launchVpn() {
        val prep: Intent? = VpnService.prepare(this)
        if (prep != null) vpnPermission.launch(prep) else IgVpnService.start(this)
    }

    // ---- rendering --------------------------------------------------------------

    private fun showMessage(text: String, error: Boolean = true) {
        message.text = text
        message.visibility = View.VISIBLE
        message.setTextColor(
            if (error) com.google.android.material.color.MaterialColors.getColor(message, com.google.android.material.R.attr.colorError)
            else com.google.android.material.color.MaterialColors.getColor(message, com.google.android.material.R.attr.colorPrimary)
        )
        handler.removeCallbacks(hideMessage)
        handler.postDelayed(hideMessage, 8000)
    }

    private val hideMessage = Runnable { message.visibility = View.GONE }

    override fun onStart() {
        super.onStart()
        EngineHolder.addListener(this)
        handler.post(refresh)
        if (Updater.dueForCheck(this)) checkForUpdates(manual = false)
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
        val status: MobileStatus = runCatching { engine.status() }.getOrNull() ?: return
        val running = IgVpnService.running
        if (toggle.isChecked != running && !toggle.isPressed) toggle.isChecked = running

        val online = status.peers.count { it.online }
        val anyLighthouse = status.networks.any { it.lighthouseConnected }
        statusTitle.text = getString(
            when {
                !running -> R.string.tunnel_off
                anyLighthouse -> R.string.tunnel_on
                else -> R.string.tunnel_starting
            }
        )
        statusDot.setBackgroundResource(
            when {
                !running -> R.drawable.dot_off
                anyLighthouse -> R.drawable.dot_on
                else -> R.drawable.dot_warn
            }
        )
        val on = status.networks.filter { it.enabled }
        statusDetail.text = when {
            status.networks.isEmpty() -> getString(R.string.no_networks)
            on.isEmpty() -> getString(R.string.networks_on, 0, status.networks.size)
            on.size < status.networks.size -> on.joinToString(", ") { it.name } + " · " + getString(R.string.networks_on, on.size, status.networks.size) + " · " + getString(R.string.peers_online, online, status.peers.size)
            else -> on.joinToString(", ") { it.name } + " · " + getString(R.string.peers_online, online, status.peers.size)
        }

        renderNetworks(status.networks)
        renderPeers(status.peers)
    }

    private fun renderNetworks(list: List<MobileNetwork>) {
        networks.removeAllViews()
        if (list.isEmpty()) {
            networks.addView(emptyRow(getString(R.string.no_networks)))
            return
        }
        val inflater = LayoutInflater.from(this)
        for (n in list) {
            val row = inflater.inflate(R.layout.item_network, networks, false)
            row.findViewById<View>(R.id.dot).setBackgroundResource(
                when {
                    !n.enabled -> R.drawable.dot_off
                    n.lighthouseConnected -> R.drawable.dot_on
                    else -> R.drawable.dot_warn
                }
            )
            row.findViewById<TextView>(R.id.name).text = n.name
            val v6 = n.address6?.let { "  $it" } ?: ""
            row.findViewById<TextView>(R.id.detail).text = "${n.address}$v6"
            val lh = if (n.lighthouseConnected) "lighthouse connected" else "lighthouse unreachable"
            row.findViewById<TextView>(R.id.extra).text =
                if (n.enabled) "${n.dnsName} · ${n.policySummary} · $lh" else "${n.dnsName} · ${getString(R.string.network_off)}"
            row.alpha = if (n.enabled) 1f else 0.6f
            val sw = row.findViewById<MaterialSwitch>(R.id.enabled)
            sw.isChecked = n.enabled
            sw.setOnCheckedChangeListener { _, checked ->
                scope.launch {
                    val r = withContext(Dispatchers.IO) { runCatching { EngineHolder.engine?.setNetworkEnabled(n.id, checked) } }
                    r.onFailure { showMessage(it.message ?: "toggle failed") }
                    render()
                }
            }
            row.findViewById<ImageButton>(R.id.leave).setOnClickListener { confirmLeave(n) }
            networks.addView(row)
        }
    }

    private fun renderPeers(list: List<MobilePeer>) {
        peers.removeAllViews()
        if (list.isEmpty()) {
            peers.addView(emptyRow(getString(R.string.no_peers)))
            return
        }
        val inflater = LayoutInflater.from(this)
        for (p in list.sortedWith(compareByDescending<MobilePeer> { it.online }.thenBy { it.hostname.lowercase() })) {
            val row = inflater.inflate(R.layout.item_peer, peers, false)
            row.findViewById<View>(R.id.dot).setBackgroundResource(if (p.online) R.drawable.dot_on else R.drawable.dot_off)
            row.findViewById<TextView>(R.id.name).text = p.hostname
            row.findViewById<TextView>(R.id.detail).text = p.addresses.joinToString("  ") { it.substringAfter('=') }
            val hs = p.lastHandshakeSecsAgo?.let { "handshake ${it}s ago" } ?: "no handshake yet"
            val traffic = "${human(p.txBytes)} up · ${human(p.rxBytes)} down"
            row.findViewById<TextView>(R.id.extra).text = (p.names.firstOrNull()?.let { "$it · " } ?: "") + "$hs · $traffic"
            val path = row.findViewById<TextView>(R.id.path)
            path.text = when {
                !p.online -> "offline"
                p.path == "direct" -> "direct"
                p.path == "relay" -> "relay"
                else -> "waiting"
            }
            peers.addView(row)
        }
    }

    private fun emptyRow(text: String): View {
        val tv = TextView(this)
        tv.text = text
        tv.setPadding(48, 36, 48, 36)
        tv.setTextColor(com.google.android.material.color.MaterialColors.getColor(tv, android.R.attr.textColorSecondary))
        return tv
    }

    private fun human(bytes: ULong): String {
        val b = bytes.toDouble()
        return when {
            b >= 1_000_000_000 -> String.format("%.1f GB", b / 1_000_000_000)
            b >= 1_000_000 -> String.format("%.1f MB", b / 1_000_000)
            b >= 1_000 -> String.format("%.0f kB", b / 1_000)
            else -> "${bytes} B"
        }
    }

    companion object {
        const val EXTRA_INVITE = "invite"
        const val EXTRA_CONNECT = "connect"
    }
}
