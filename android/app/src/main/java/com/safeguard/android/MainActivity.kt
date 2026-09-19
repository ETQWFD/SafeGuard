package com.safeguard.android

import android.Manifest
import android.app.Activity
import android.content.Intent
import android.content.pm.PackageManager
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.widget.*
import androidx.activity.result.contract.ActivityResultContracts
import androidx.appcompat.app.AppCompatActivity
import androidx.core.content.ContextCompat
import com.safeguard.android.core.*
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.launch
import java.io.File

class MainActivity : AppCompatActivity() {

    private lateinit var db: VirusDb
    private lateinit var scanner: Scanner
    private lateinit var vt: VtClient
    private lateinit var quarantine: Quarantine
    private lateinit var whitelist: Whitelist
    private var scanJob: Job? = null

    // 视图
    private lateinit var tabScan: LinearLayout
    private lateinit var tabQuarantine: LinearLayout
    private lateinit var tabSettings: LinearLayout
    private lateinit var tabAbout: LinearLayout
    private lateinit var pageScan: LinearLayout
    private lateinit var pageQuarantine: LinearLayout
    private lateinit var pageSettings: LinearLayout
    private lateinit var pageAbout: LinearLayout

    private val storagePermission = registerForActivityResult(
        ActivityResultContracts.RequestPermission()) { refreshStatus() }

    private val docTree = registerForActivityResult(
        ActivityResultContracts.OpenDocumentTree()) { uri: Uri? ->
        if (uri != null) {
            contentResolver.takePersistableUriPermission(
                uri, Intent.FLAG_GRANT_READ_URI_PERMISSION)
            startSafeScan(uri)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        Thread.setDefaultUncaughtExceptionHandler { _, e ->
            android.util.Log.e("SafeGuard", "crash", e)
        }
        try {
            setContentView(R.layout.activity_main)

            db = VirusDb(this)
            db.load()
            scanner = Scanner(db)
            vt = VtClient(this)
            quarantine = Quarantine(this)
            whitelist = Whitelist(this)

            bindViews()
            setupTabs()
            setupActions()
            showTab(pageScan, tabScan)
            refreshStatus()
        } catch (e: Throwable) {
            android.util.Log.e("SafeGuard", "init failed", e)
            setContentView(android.widget.LinearLayout(this).apply {
                orientation = android.widget.LinearLayout.VERTICAL
                addView(android.widget.TextView(this@MainActivity).apply {
                    text = "SafeGuard 启动异常：${e.message}\n请重试或反馈。"
                    setPadding(48, 96, 48, 48)
                    textSize = 16f
                })
            })
        }
    }

    private fun bindViews() {
        tabScan = findViewById(R.id.tab_scan)
        tabQuarantine = findViewById(R.id.tab_quarantine)
        tabSettings = findViewById(R.id.tab_settings)
        tabAbout = findViewById(R.id.tab_about)
        pageScan = findViewById(R.id.page_scan)
        pageQuarantine = findViewById(R.id.page_quarantine)
        pageSettings = findViewById(R.id.page_settings)
        pageAbout = findViewById(R.id.page_about)
    }

    private fun setupTabs() {
        tabScan.setOnClickListener { showTab(pageScan, tabScan) }
        tabQuarantine.setOnClickListener { showTab(pageQuarantine, tabQuarantine) }
        tabSettings.setOnClickListener { showTab(pageSettings, tabSettings) }
        tabAbout.setOnClickListener { showTab(pageAbout, tabAbout) }
    }

    private fun showTab(page: LinearLayout, tab: LinearLayout) {
        listOf(pageScan, pageQuarantine, pageSettings, pageAbout)
            .forEach { it.visibility = if (it === page) LinearLayout.VISIBLE else LinearLayout.GONE }
        listOf(tabScan, tabQuarantine, tabSettings, tabAbout).forEach { t ->
            t.alpha = if (t === tab) 1.0f else 0.5f
        }
        if (page === pageQuarantine) refreshQuarantine()
        if (page === pageSettings) refreshSettings()
    }

    // ---------- 扫描页 ----------

    private fun setupActions() {
        findViewById<Button>(R.id.btn_quick).setOnClickListener { startRootScan() }
        findViewById<Button>(R.id.btn_custom).setOnClickListener {
            docTree.launch(null)
        }
        findViewById<Button>(R.id.btn_cancel).setOnClickListener {
            scanJob?.cancel()
        }
        findViewById<Button>(R.id.btn_q_restore).setOnClickListener { restoreSelected() }
        findViewById<Button>(R.id.btn_q_delete).setOnClickListener { deleteSelected() }
        findViewById<Button>(R.id.btn_save_key).setOnClickListener {
            val key = findViewById<EditText>(R.id.et_api_key).text.toString().trim()
            vt.setApiKey(key)
            toast(getString(R.string.saved))
        }
        findViewById<Button>(R.id.btn_permission).setOnClickListener {
            requestStorage()
        }
        findViewById<Button>(R.id.btn_wl_add).setOnClickListener {
            docTree.launch(null)
        }
        findViewById<Button>(R.id.btn_refresh_db).setOnClickListener {
            toast("当前病毒库 ${db.size()} 条")
        }
    }

    private fun requestStorage() {
        if (Build.VERSION.SDK_INT >= 30) {
            startActivity(Intent(
                Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION,
                Uri.parse("package:$packageName")))
        } else {
            storagePermission.launch(Manifest.permission.READ_EXTERNAL_STORAGE)
        }
    }

    private fun hasStorageAccess(): Boolean {
        return if (Build.VERSION.SDK_INT >= 30)
            android.os.Environment.isExternalStorageManager()
        else ContextCompat.checkSelfPermission(
            this, Manifest.permission.READ_EXTERNAL_STORAGE) ==
            PackageManager.PERMISSION_GRANTED
    }

    private fun refreshStatus() {
        val ok = hasStorageAccess()
        findViewById<TextView>(R.id.tv_status).text =
            if (ok) getString(R.string.status_ok) else getString(R.string.status_need_permission)
        findViewById<Button>(R.id.btn_permission).visibility =
            if (ok) android.view.View.GONE else android.view.View.VISIBLE
    }

    private fun startRootScan() {
        if (!hasStorageAccess()) {
            toast(getString(R.string.need_permission))
            return
        }
        startLocalScan(File("/storage/emulated/0"))
    }

    /** SAF 树 Uri 扫描 */
    private fun startSafeScan(treeUri: Uri) {
        val docFile = androidx.documentfile.provider.DocumentFile.fromTreeUri(this, treeUri)
        if (docFile == null) {
            toast(getString(R.string.scan_failed))
            return
        }
        val progress = findViewById<ProgressBar>(R.id.progress)
        val tv = findViewById<TextView>(R.id.tv_progress)
        val results = findViewById<TextView>(R.id.tv_results)
        scanJob = CoroutineScope(Dispatchers.IO).launch {
            var count = 0
            var infected = 0
            var suspicious = 0
            suspend fun walk(doc: androidx.documentfile.provider.DocumentFile, depth: Int) {
                if (depth > 3 || scanJob?.isActive == false) return
                doc.listFiles().forEach { child ->
                    if (child.isDirectory) walk(child, depth + 1)
                    else {
                        count++
                        val uri = child.uri
                        val file = copyUriToCache(uri)
                        if (file != null) {
                            val r = scanner.scanFile(file, vt, useCloud = true)
                            if (r.status == "infected") infected++
                            else if (r.status == "suspicious") suspicious++
                            file.delete()
                        }
                        runOnUiThread {
                            progress.progress = count % 100
                            tv.text = getString(R.string.scanning) + " $count · ${child.name}"
                        }
                    }
                }
            }
            walk(docFile, 0)
            runOnUiThread {
                results.text = getString(R.string.scan_done, count, infected, suspicious)
                toast(getString(R.string.scan_finished))
            }
        }
    }

    /** 本地目录扫描 */
    private fun startLocalScan(root: File) {
        val progress = findViewById<ProgressBar>(R.id.progress)
        val tv = findViewById<TextView>(R.id.tv_progress)
        val results = findViewById<TextView>(R.id.tv_results)
        scanJob = CoroutineScope(Dispatchers.IO).launch {
            val found = scanner.scanDirectory(
                root, maxDepth = 4,
                onProgress = { count, name ->
                    // 限速 UI 更新：每 15 个文件或约 300ms 才刷新一次，避免主线程被淹没
                    if (count % 15 == 0) {
                        runOnUiThread {
                            progress.isIndeterminate = false
                            tv.text = getString(R.string.scanning) + " $count · $name"
                        }
                    }
                },
                vtClient = vt, useCloud = true)
            val infected = found.count { it.status == "infected" }
            val suspicious = found.count { it.status == "suspicious" }
            runOnUiThread {
                results.text = getString(R.string.scan_done, found.size, infected, suspicious)
                results.append("\n")
                found.take(20).forEach { r ->
                    results.append("⚠ ${r.threatName}  ${r.path}\n")
                }
                toast(getString(R.string.scan_finished))
            }
        }
    }

    private fun copyUriToCache(uri: Uri): File? {
        return try {
            val name = "cache_" + System.currentTimeMillis() + ".bin"
            val out = File(cacheDir, name)
            contentResolver.openInputStream(uri)?.use { input ->
                out.outputStream().use { output -> input.copyTo(output) }
            }
            out
        } catch (e: Exception) {
            null
        }
    }

    // ---------- 隔离区 ----------

    private var selectedQid: String? = null

    private fun refreshQuarantine() {
        val list = findViewById<ListView>(R.id.list_quarantine)
        val items = quarantine.list()
        val adapter = ArrayAdapter(this, android.R.layout.simple_list_item_1,
            items.map { "${it.optString("name")}  (${it.optString("date")})" })
        list.adapter = adapter
        list.setOnItemClickListener { _, _, pos, _ ->
            selectedQid = items[pos].optString("id")
        }
    }

    private fun restoreSelected() {
        val id = selectedQid ?: return
        if (quarantine.restore(id)) toast(getString(R.string.restored)) else toast(getString(R.string.failed))
        refreshQuarantine()
    }

    private fun deleteSelected() {
        val id = selectedQid ?: return
        quarantine.remove(id)
        toast(getString(R.string.deleted))
        refreshQuarantine()
    }

    // ---------- 设置 ----------

    private fun refreshSettings() {
        findViewById<EditText>(R.id.et_api_key).setText(vt.apiKey())
        findViewById<TextView>(R.id.tv_db_info).text =
            getString(R.string.db_info, db.size())
        findViewById<TextView>(R.id.tv_whitelist).text =
            whitelist.customPaths().joinToString("\n") { it } ?: ""
        refreshStatus()
    }

    override fun onResume() {
        super.onResume()
        refreshStatus()
    }

    private fun toast(msg: String) {
        Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
    }
}
