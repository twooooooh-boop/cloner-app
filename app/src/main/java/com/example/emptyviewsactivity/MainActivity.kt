package com.example.emptyviewsactivity

import android.app.PendingIntent
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.PackageInstaller
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Bundle
import android.provider.Settings
import android.webkit.JavascriptInterface
import android.webkit.ValueCallback
import android.webkit.WebChromeClient
import android.webkit.WebView
import android.widget.Toast
import org.json.JSONObject
import java.io.File
import androidx.activity.enableEdgeToEdge
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import androidx.core.view.ViewCompat
import androidx.core.view.WindowInsetsCompat

class MainActivity : AppCompatActivity() {
    private var filePathCallback: ValueCallback<Array<Uri>>? = null
    private var pendingText: String = ""
    private lateinit var web: WebView
    private var apkInput: File? = null
    private var apkOutput: File? = null
    @Volatile private var building = false

    private val pickFile = registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        filePathCallback?.onReceiveValue(if (uri != null) arrayOf(uri) else null)
        filePathCallback = null
    }

    private val saveFile = registerForActivityResult(ActivityResultContracts.CreateDocument("application/xml")) { uri ->
        if (uri != null) {
            contentResolver.openOutputStream(uri)?.use { it.write(pendingText.toByteArray()) }
            Toast.makeText(this, "Saved", Toast.LENGTH_SHORT).show()
        }
    }

    private val apkPicker = registerForActivityResult(ActivityResultContracts.GetContent()) { uri ->
        if (uri != null) loadApk(uri)
    }

    private val apkSaver = registerForActivityResult(ActivityResultContracts.CreateDocument("application/vnd.android.package-archive")) { uri ->
        val built = apkOutput
        if (uri == null || built == null || !built.exists()) {
            jsStatus("Not saved. You can still press Install now, or Build again.", "warn")
        } else {
            Thread {
                try {
                    contentResolver.openOutputStream(uri)?.use { out -> built.inputStream().use { it.copyTo(out) } }
                        ?: throw IllegalStateException("Could not write to that location.")
                    jsStatus("Saved. You can also press Install now to see exactly what Android says.", "ok")
                } catch (e: Exception) {
                    jsStatus("Could not save: " + (e.message ?: e.javaClass.simpleName), "err")
                }
            }.start()
        }
    }

    private fun js(code: String) {
        runOnUiThread {
            try {
                web.evaluateJavascript(code, null)
            } catch (e: Exception) {
                // page is gone, nothing to update
            }
        }
    }

    private fun jsStatus(text: String, kind: String) {
        js("window.onApkStatus(" + JSONObject.quote(text) + "," + JSONObject.quote(kind) + ")")
    }

    private fun loadApk(uri: Uri) {
        jsStatus("Reading the APK...", "")
        Thread {
            try {
                val f = File(cacheDir, "input.apk")
                contentResolver.openInputStream(uri)?.use { input -> f.outputStream().use { input.copyTo(it) } }
                    ?: throw IllegalStateException("Could not open that file.")
                val info = ApkBuilder.inspect(f)
                apkInput = f
                val o = JSONObject()
                o.put("pkg", info.packageName)
                o.put("labelKind", info.labelKind)
                o.put("label", info.label)
                o.put("shared", info.sharedUserId)
                o.put("split", info.splitNote)
                o.put("size", f.length())
                js("window.onApkPicked(" + o.toString() + ")")
                jsStatus("", "")
            } catch (e: Exception) {
                apkInput = null
                jsStatus("Could not read that APK: " + (e.message ?: e.javaClass.simpleName), "err")
            }
        }.start()
    }

    private val installAction = "com.example.emptyviewsactivity.INSTALL_RESULT"

    private val installReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context, intent: Intent) {
            val status = intent.getIntExtra(PackageInstaller.EXTRA_STATUS, PackageInstaller.STATUS_FAILURE)
            val msg = intent.getStringExtra(PackageInstaller.EXTRA_STATUS_MESSAGE) ?: ""
            when (status) {
                PackageInstaller.STATUS_PENDING_USER_ACTION -> {
                    @Suppress("DEPRECATION")
                    val confirm = intent.getParcelableExtra<Intent>(Intent.EXTRA_INTENT)
                    if (confirm != null) startActivity(confirm)
                }
                PackageInstaller.STATUS_SUCCESS -> jsStatus("Installed. Open it from your app list.", "ok")
                else -> jsStatus("Android refused the install. Code " + status + ". " + msg, "err")
            }
        }
    }

    /** Installs the built APK through Android's own installer API, so a refusal comes with the real reason. */
    private fun startInstall() {
        val f = apkOutput
        if (f == null || !f.exists()) {
            jsStatus("Build an APK first.", "err")
            return
        }
        if (!packageManager.canRequestPackageInstalls()) {
            jsStatus("Allow Cloner to install apps on the screen that just opened, come back, and press Install now again.", "warn")
            startActivity(Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES, Uri.parse("package:" + packageName)))
            return
        }
        Thread {
            try {
                val installer = packageManager.packageInstaller
                val id = installer.createSession(PackageInstaller.SessionParams(PackageInstaller.SessionParams.MODE_FULL_INSTALL))
                installer.openSession(id).use { session ->
                    f.inputStream().use { ins ->
                        session.openWrite("base.apk", 0, f.length()).use { out ->
                            ins.copyTo(out)
                            session.fsync(out)
                        }
                    }
                    val pi = PendingIntent.getBroadcast(
                        this, id, Intent(installAction).setPackage(packageName),
                        PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_MUTABLE
                    )
                    session.commit(pi.intentSender)
                }
                jsStatus("Installing. Confirm on the Android screen if it asks.", "")
            } catch (e: Exception) {
                jsStatus("Could not start the install: " + (e.message ?: e.javaClass.simpleName), "err")
            }
        }.start()
    }

    override fun onDestroy() {
        super.onDestroy()
        try {
            unregisterReceiver(installReceiver)
        } catch (e: Exception) {
            // was not registered
        }
    }

    inner class Bridge {
        @JavascriptInterface
        fun save(name: String, text: String) {
            pendingText = text
            runOnUiThread { saveFile.launch(name) }
        }

        @JavascriptInterface
        fun installApk() {
            runOnUiThread { startInstall() }
        }

        @JavascriptInterface
        fun pickApk() {
            runOnUiThread { apkPicker.launch("*/*") }
        }

        @JavascriptInterface
        fun buildApk(pkg: String, label: String, mode: String, keyMode: String) {
            val input = apkInput
            if (input == null || !input.exists()) {
                jsStatus("Choose an APK first.", "err")
                return
            }
            if (building) return
            building = true
            Thread {
                try {
                    jsStatus("Patching and signing. Big apps can take a minute.", "")
                    val out = File(cacheDir, "output.apk")
                    val key = if (keyMode == "phone") SigningKeys.loadOrCreate(File(filesDir, "signing"))
                    else SigningKeys.loadOrCreate(File(filesDir, "signing")) { assets.open(it) }
                    val c = ApkBuilder.build(input, out, pkg, label, key, mode)
                    apkOutput = out
                    // ask Android itself to read and verify the finished file
                    val pi = packageManager.getPackageArchiveInfo(out.absolutePath, PackageManager.GET_SIGNING_CERTIFICATES)
                    val signers = pi?.signingInfo?.apkContentsSigners
                    if (pi == null) {
                        c.warn = true
                        c.note += " WARNING: Android's own parser could not read the finished APK."
                    } else if (signers == null || signers.isEmpty()) {
                        c.warn = true
                        c.note += " WARNING: Android found no valid signature in the finished APK."
                    } else {
                        c.note += " Android parsed it OK as " + pi.packageName + "."
                    }
                    val o = JSONObject()
                    o.put("pkg", c.pkg)
                    o.put("auth", c.auth)
                    o.put("perm", c.perm)
                    o.put("aff", c.aff)
                    o.put("rel", c.rel)
                    o.put("lbl", c.lbl)
                    o.put("lblMissing", c.lblMissing)
                    o.put("note", c.note)
                    o.put("warn", c.warn)
                    js("window.onApkBuilt(" + o.toString() + ")")
                    runOnUiThread { apkSaver.launch(pkg + ".apk") }
                } catch (e: Throwable) {
                    jsStatus("Build failed: " + (e.message ?: e.javaClass.simpleName), "err")
                } finally {
                    building = false
                }
            }.start()
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContentView(R.layout.activity_main)
        ViewCompat.setOnApplyWindowInsetsListener(findViewById(R.id.main)) { v, insets ->
            val systemBars = insets.getInsets(WindowInsetsCompat.Type.systemBars())
            v.setPadding(systemBars.left, systemBars.top, systemBars.right, systemBars.bottom)
            insets
        }

        web = findViewById(R.id.web)
        ContextCompat.registerReceiver(this, installReceiver, IntentFilter(installAction), ContextCompat.RECEIVER_NOT_EXPORTED)
        web.settings.javaScriptEnabled = true
        web.addJavascriptInterface(Bridge(), "AndroidBridge")
        web.webChromeClient = object : WebChromeClient() {
            override fun onShowFileChooser(
                view: WebView?,
                callback: ValueCallback<Array<Uri>>?,
                params: FileChooserParams?
            ): Boolean {
                filePathCallback?.onReceiveValue(null)
                filePathCallback = callback
                pickFile.launch("*/*")
                return true
            }
        }
        web.loadUrl("file:///android_asset/Cloner.html")
    }
}
