package com.example.emptyviewsactivity

import java.io.ByteArrayOutputStream

class ManifestInfo(
    val packageName: String,
    val labelKind: String, // "string", "resource" or "none"
    val label: String,
    val sharedUserId: Boolean,
    val splitNote: String // empty when the APK is a normal standalone one
)

class PatchCounts {
    var pkg = 0
    var auth = 0
    var perm = 0
    var aff = 0
    var rel = 0
    var lbl = 0
    var lblMissing = false
    var changed = 0
    var note = ""
    var warn = false
}

class PatchResult(val bytes: ByteArray, val counts: PatchCounts)

/**
 * Edits a compiled (binary) AndroidManifest.xml in place.
 * Same rules as the manifest patcher in Cloner.html, but on the binary format.
 */
object AxmlPatcher {
    private const val ANDROID_NS = "http://schemas.android.com/apk/res/android"
    private const val T_XML = 0x0003
    private const val T_POOL = 0x0001
    private const val T_RESMAP = 0x0180
    private const val T_START = 0x0102
    private const val TYPE_REFERENCE = 0x01
    private const val TYPE_STRING = 0x03

    private val RES_NAMES = mapOf(
        0x01010001 to "label",
        0x01010003 to "name",
        0x01010006 to "permission",
        0x01010007 to "readPermission",
        0x01010008 to "writePermission",
        0x01010011 to "process",
        0x01010012 to "taskAffinity",
        0x01010018 to "authorities"
    )

    private val PERM_TAGS: Set<String> = run {
        val s = HashSet<String>()
        for (p in listOf("", "uses-")) {
            for (x in listOf("", "-group", "-tree", "-sdk-23", "-sdk-m")) s.add(p + "permission" + x)
        }
        s
    }
    private val CLASS_TAGS = setOf(
        "application", "activity-alias", "activity", "service", "receiver", "provider", "instrumentation"
    )
    private val CLASS_ATTRS = setOf(
        "name", "targetActivity", "parentActivityName", "backupAgent", "appComponentFactory", "manageSpaceActivity"
    )

    // ---------- byte helpers ----------
    private fun u8(a: ByteArray, o: Int) = a[o].toInt() and 0xFF
    private fun u16(a: ByteArray, o: Int) = u8(a, o) or (u8(a, o + 1) shl 8)
    private fun i32(a: ByteArray, o: Int) =
        u8(a, o) or (u8(a, o + 1) shl 8) or (u8(a, o + 2) shl 16) or (u8(a, o + 3) shl 24)

    private fun put16(a: ByteArray, o: Int, v: Int) {
        a[o] = v.toByte(); a[o + 1] = (v shr 8).toByte()
    }

    private fun put32(a: ByteArray, o: Int, v: Int) {
        a[o] = v.toByte(); a[o + 1] = (v shr 8).toByte(); a[o + 2] = (v shr 16).toByte(); a[o + 3] = (v shr 24).toByte()
    }

    // ---------- string pool ----------
    private class Pool(
        val strings: MutableList<String>,
        val raws: MutableList<ByteArray?>,
        val utf8: Boolean,
        val flags: Int,
        val styleCount: Int,
        val styleOffsets: ByteArray,
        val styleData: ByteArray
    ) {
        fun intern(s: String): Int {
            val i = strings.indexOf(s)
            if (i >= 0) return i
            strings.add(s)
            raws.add(null)
            return strings.size - 1
        }

        fun str(i: Int): String? = if (i >= 0 && i < strings.size) strings[i] else null
    }

    private fun readPool(a: ByteArray, p: Int): Pool {
        val size = i32(a, p + 4)
        val count = i32(a, p + 8)
        val styleCount = i32(a, p + 12)
        val flags = i32(a, p + 16)
        val stringsStart = i32(a, p + 20)
        val stylesStart = i32(a, p + 24)
        val utf8 = (flags and 0x100) != 0
        val strings = ArrayList<String>(count)
        val raws = ArrayList<ByteArray?>(count)
        for (i in 0 until count) {
            val off = p + stringsStart + i32(a, p + 28 + 4 * i)
            var q = off
            val s: String
            val end: Int
            if (utf8) {
                var l1 = u8(a, q); q++
                if (l1 and 0x80 != 0) { l1 = ((l1 and 0x7F) shl 8) or u8(a, q); q++ }
                var l2 = u8(a, q); q++
                if (l2 and 0x80 != 0) { l2 = ((l2 and 0x7F) shl 8) or u8(a, q); q++ }
                s = String(a, q, l2, Charsets.UTF_8)
                end = q + l2 + 1
            } else {
                var l = u16(a, q); q += 2
                if (l and 0x8000 != 0) { l = ((l and 0x7FFF) shl 16) or u16(a, q); q += 2 }
                s = String(a, q, l * 2, Charsets.UTF_16LE)
                end = q + l * 2 + 2
            }
            strings.add(s)
            raws.add(a.copyOfRange(off, end))
        }
        val styleOffsets = a.copyOfRange(p + 28 + 4 * count, p + 28 + 4 * count + 4 * styleCount)
        val styleData = if (styleCount > 0) a.copyOfRange(p + stylesStart, p + size) else ByteArray(0)
        return Pool(strings, raws, utf8, flags, styleCount, styleOffsets, styleData)
    }

    private fun writeLen8(o: ByteArrayOutputStream, n: Int) {
        if (n > 0x7F) { o.write((n shr 8) or 0x80); o.write(n and 0xFF) } else o.write(n)
    }

    private fun writeLen16(o: ByteArrayOutputStream, n: Int) {
        if (n > 0x7FFF) {
            val hi = (n shr 16) or 0x8000
            o.write(hi and 0xFF); o.write((hi shr 8) and 0xFF)
            o.write(n and 0xFF); o.write((n shr 8) and 0xFF)
        } else {
            o.write(n and 0xFF); o.write((n shr 8) and 0xFF)
        }
    }

    private fun encodeString(s: String, utf8: Boolean): ByteArray {
        val o = ByteArrayOutputStream()
        if (utf8) {
            val b = s.toByteArray(Charsets.UTF_8)
            writeLen8(o, s.length)
            writeLen8(o, b.size)
            o.write(b)
            o.write(0)
        } else {
            writeLen16(o, s.length)
            o.write(s.toByteArray(Charsets.UTF_16LE))
            o.write(0); o.write(0)
        }
        return o.toByteArray()
    }

    private fun buildPool(pool: Pool): ByteArray {
        val n = pool.strings.size
        val recs = (0 until n).map { pool.raws[it] ?: encodeString(pool.strings[it], pool.utf8) }
        val total = recs.sumOf { it.size }
        val padded = (total + 3) and 3.inv()
        val stringsStart = 28 + 4 * n + pool.styleOffsets.size
        val stylesStart = if (pool.styleCount > 0) stringsStart + padded else 0
        val size = stringsStart + padded + pool.styleData.size
        val out = ByteArray(size)
        put16(out, 0, T_POOL)
        put16(out, 2, 28)
        put32(out, 4, size)
        put32(out, 8, n)
        put32(out, 12, pool.styleCount)
        put32(out, 16, pool.flags and 1.inv()) // never mark it as sorted
        put32(out, 20, stringsStart)
        put32(out, 24, stylesStart)
        var off = 0
        for (i in 0 until n) {
            put32(out, 28 + 4 * i, off)
            System.arraycopy(recs[i], 0, out, stringsStart + off, recs[i].size)
            off += recs[i].size
        }
        System.arraycopy(pool.styleOffsets, 0, out, 28 + 4 * n, pool.styleOffsets.size)
        System.arraycopy(pool.styleData, 0, out, stringsStart + padded, pool.styleData.size)
        return out
    }

    // ---------- document ----------
    private class Doc(
        val a: ByteArray,
        val pool: Pool,
        val poolOff: Int,
        val poolSize: Int,
        val resMap: IntArray,
        val starts: List<Int>
    ) {
        fun tag(el: Int): String = pool.str(i32(a, el + 20)) ?: ""
        fun attrCount(el: Int) = u16(a, el + 28)
        fun attrBase(el: Int, i: Int): Int {
            val start = u16(a, el + 24)
            var size = u16(a, el + 26)
            if (size < 20) size = 20
            return el + 16 + start + i * size
        }

        fun attrName(nameIdx: Int): String {
            val rid = if (nameIdx >= 0 && nameIdx < resMap.size) resMap[nameIdx] else 0
            RES_NAMES[rid]?.let { return it }
            return pool.str(nameIdx) ?: ""
        }

        fun isAndroid(ns: Int, nameIdx: Int): Boolean {
            if (ns >= 0 && pool.str(ns) == ANDROID_NS) return true
            val rid = if (nameIdx >= 0 && nameIdx < resMap.size) resMap[nameIdx] else 0
            return RES_NAMES.containsKey(rid)
        }
    }

    private fun parse(data: ByteArray): Doc {
        if (data.size < 16 || u16(data, 0) != T_XML) throw IllegalArgumentException("This is not a compiled AndroidManifest.xml")
        val a = data.copyOf()
        var off = u16(a, 2)
        var pool: Pool? = null
        var poolOff = -1
        var poolSize = 0
        var resMap = IntArray(0)
        val starts = ArrayList<Int>()
        while (off + 8 <= a.size) {
            val type = u16(a, off)
            val size = i32(a, off + 4)
            if (size < 8 || off + size > a.size) throw IllegalArgumentException("The manifest is damaged")
            when (type) {
                T_POOL -> if (pool == null) { pool = readPool(a, off); poolOff = off; poolSize = size }
                T_RESMAP -> {
                    val n = (size - 8) / 4
                    resMap = IntArray(n) { i32(a, off + 8 + 4 * it) }
                }
                T_START -> starts.add(off)
            }
            off += size
        }
        if (pool == null) throw IllegalArgumentException("The manifest has no string table")
        return Doc(a, pool, poolOff, poolSize, resMap, starts)
    }

    private fun manifestPackage(d: Doc): String? {
        for (el in d.starts) {
            if (d.tag(el) != "manifest") continue
            for (i in 0 until d.attrCount(el)) {
                val b = d.attrBase(el, i)
                if (i32(d.a, b) == -1 && d.attrName(i32(d.a, b + 4)) == "package" && u8(d.a, b + 15) == TYPE_STRING)
                    return d.pool.str(i32(d.a, b + 16))
            }
            return null
        }
        return null
    }

    // ---------- public API ----------
    fun inspect(data: ByteArray): ManifestInfo {
        val d = parse(data)
        val pkg = manifestPackage(d) ?: throw IllegalArgumentException("No package name found in the manifest")
        var kind = "none"
        var label = ""
        var shared = false
        var split = ""
        for (el in d.starts) {
            val tag = d.tag(el)
            if (tag == "meta-data") {
                var key = ""
                var truthy = false
                for (i in 0 until d.attrCount(el)) {
                    val b = d.attrBase(el, i)
                    val nm = d.attrName(i32(d.a, b + 4))
                    val t = u8(d.a, b + 15)
                    if (nm == "name" && t == TYPE_STRING) key = d.pool.str(i32(d.a, b + 16)) ?: ""
                    if (nm == "value") {
                        truthy = if (t == TYPE_STRING) d.pool.str(i32(d.a, b + 16)) == "true" else i32(d.a, b + 16) != 0
                    }
                }
                if (key == "com.android.vending.splits.required" && truthy)
                    split = "This APK needs split APKs to run (an app bundle). A single base APK will not install."
                continue
            }
            if (tag != "application" && tag != "manifest") continue
            for (i in 0 until d.attrCount(el)) {
                val b = d.attrBase(el, i)
                val ns = i32(d.a, b)
                val nameIdx = i32(d.a, b + 4)
                if (tag == "manifest" && d.attrName(nameIdx) == "split")
                    split = "This is a split APK (a piece of an app bundle), not a full app."
                if (!d.isAndroid(ns, nameIdx)) continue
                val name = d.attrName(nameIdx)
                if (name == "isSplitRequired" && i32(d.a, b + 16) != 0 && split.isEmpty())
                    split = "This APK needs split APKs to run (an app bundle). A single base APK will not install."
                if (name == "requiredSplitTypes" && split.isEmpty())
                    split = "This APK needs split APKs to run (an app bundle). A single base APK will not install."
                if (tag == "manifest" && name == "sharedUserId") shared = true
                if (tag == "application" && name == "label" && kind == "none") {
                    val type = u8(d.a, b + 15)
                    if (type == TYPE_STRING) { kind = "string"; label = d.pool.str(i32(d.a, b + 16)) ?: "" }
                    else if (type == TYPE_REFERENCE) kind = "resource"
                }
            }
        }
        return ManifestInfo(pkg, kind, label, shared, split)
    }

    fun patch(data: ByteArray, newPkg: String, newLabel: String): PatchResult {
        val d = parse(data)
        val a = d.a
        val pool = d.pool
        val old = manifestPackage(d) ?: throw IllegalArgumentException("No package name found in the manifest")
        if (old == newPkg) throw IllegalArgumentException("That matches the original package. Pick a different name.")
        val c = PatchCounts()

        fun swap(v: String): String {
            if (v == old || v.startsWith("$old.")) { c.changed++; return newPkg + v.substring(old.length) }
            return v
        }

        fun setStr(base: Int, value: String) {
            val idx = pool.intern(value)
            put32(a, base + 8, idx)
            put32(a, base + 16, idx)
            a[base + 15] = TYPE_STRING.toByte()
        }

        for (el in d.starts) {
            val tag = d.tag(el)
            for (i in 0 until d.attrCount(el)) {
                val b = d.attrBase(el, i)
                val ns = i32(a, b)
                val nameIdx = i32(a, b + 4)
                val type = u8(a, b + 15)
                val sval = if (type == TYPE_STRING) pool.str(i32(a, b + 16)) else null
                if (sval == null) continue
                val name = d.attrName(nameIdx)

                if (tag == "manifest" && ns == -1 && name == "package") {
                    if (sval == old) { setStr(b, newPkg); c.pkg++; c.changed++ }
                    continue
                }
                if (!d.isAndroid(ns, nameIdx)) continue

                when (name) {
                    "authorities" -> {
                        val n = sval.split(';').joinToString(";") { swap(it) }
                        if (n != sval) { setStr(b, n); c.auth++ }
                    }
                    "taskAffinity" -> {
                        val n = swap(sval)
                        if (n != sval) { setStr(b, n); c.aff++ }
                    }
                    "permission", "readPermission", "writePermission", "process" -> {
                        val n = swap(sval)
                        if (n != sval) { setStr(b, n); c.perm++ }
                    }
                }
                if (name == "name" && tag in PERM_TAGS) {
                    val n = swap(sval)
                    if (n != sval) { setStr(b, n); c.perm++ }
                }
                if (tag in CLASS_TAGS && name in CLASS_ATTRS) {
                    if (sval.startsWith(".")) { setStr(b, old + sval); c.rel++ }
                    else if (sval.isNotEmpty() && sval.none { it == '.' || it == '@' || it == '?' }) {
                        setStr(b, "$old.$sval"); c.rel++
                    }
                }
            }
        }

        // app name: whatever the <application> label points at, swap every use of that same value
        if (newLabel.isNotBlank()) {
            var appType = -1
            var appData = 0
            var appStr: String? = null
            for (el in d.starts) {
                if (d.tag(el) != "application") continue
                for (i in 0 until d.attrCount(el)) {
                    val b = d.attrBase(el, i)
                    val nameIdx = i32(a, b + 4)
                    if (d.isAndroid(i32(a, b), nameIdx) && d.attrName(nameIdx) == "label") {
                        appType = u8(a, b + 15)
                        appData = i32(a, b + 16)
                        appStr = if (appType == TYPE_STRING) pool.str(appData) else null
                    }
                }
                break
            }
            if (appType < 0) {
                c.lblMissing = true
            } else {
                for (el in d.starts) {
                    for (i in 0 until d.attrCount(el)) {
                        val b = d.attrBase(el, i)
                        val nameIdx = i32(a, b + 4)
                        if (!d.isAndroid(i32(a, b), nameIdx) || d.attrName(nameIdx) != "label") continue
                        val t = u8(a, b + 15)
                        if (t != appType) continue
                        val same = if (t == TYPE_STRING) pool.str(i32(a, b + 16)) == appStr else i32(a, b + 16) == appData
                        if (same) { setStr(b, newLabel); c.lbl++ }
                    }
                }
            }
        }

        val newPool = buildPool(pool)
        val out = ByteArrayOutputStream(a.size + newPool.size)
        out.write(a, 0, d.poolOff)
        out.write(newPool)
        out.write(a, d.poolOff + d.poolSize, a.size - d.poolOff - d.poolSize)
        val res = out.toByteArray()
        put32(res, 4, res.size)
        return PatchResult(res, c)
    }
}
