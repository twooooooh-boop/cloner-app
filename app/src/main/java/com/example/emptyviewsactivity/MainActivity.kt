package com.example.emptyviewsactivity

import android.net.Uri
import android.os.Bundle
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
            built?.delete()
            jsStatus("Save cancelled. Press Build again to retry.", "warn")
        } else {
            Thread {
                try {
                    contentResolver.openOutputStream(uri)?.use { out -> built.inputStream().use { it.copyTo(out) } }
                        ?: throw IllegalStateException("Could not write to that location.")
                    built.delete()
                    jsStatus("Saved. Open the APK from your file manager to install it.", "ok")
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
                o.put("size", f.length())
                js("window.onApkPicked(" + o.toString() + ")")
                jsStatus("", "")
            } catch (e: Exception) {
                apkInput = null
                jsStatus("Could not read that APK: " + (e.message ?: e.javaClass.simpleName), "err")
            }
        }.start()
    }

    inner class Bridge {
        @JavascriptInterface
        fun save(name: String, text: String) {
            pendingText = text
            runOnUiThread { saveFile.launch(name) }
        }

        @JavascriptInterface
        fun pickApk() {
            runOnUiThread { apkPicker.launch("*/*") }
        }

        @JavascriptInterface
        fun buildApk(pkg: String, label: String) {
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
                    val key = SigningKeys.loadOrCreate(File(filesDir, "signing")) { assets.open(it) }
                    val c = ApkBuilder.build(input, out, pkg, label, key)
                    apkOutput = out
                    val o = JSONObject()
                    o.put("pkg", c.pkg)
                    o.put("auth", c.auth)
                    o.put("perm", c.perm)
                    o.put("aff", c.aff)
                    o.put("rel", c.rel)
                    o.put("lbl", c.lbl)
                    o.put("lblMissing", c.lblMissing)
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
