package com.example.emptyviewsactivity

import com.android.apksig.ApkSigner
import com.android.apksig.ApkVerifier
import java.io.BufferedOutputStream
import java.io.ByteArrayOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.OutputStream
import java.io.RandomAccessFile
import java.security.MessageDigest
import java.util.zip.CRC32
import java.util.zip.Deflater
import java.util.zip.DeflaterOutputStream
import java.util.zip.ZipFile

/**
 * Same order as the professional tools (apksigner, uber-apk-signer, Android's own build):
 * 1. patch the manifest, 2. zipalign by copying every other entry byte for byte, 3. sign last, 4. verify.
 */
object ApkBuilder {
    private const val MANIFEST = "AndroidManifest.xml"

    fun inspect(apk: File): ManifestInfo {
        ZipFile(apk).use { zf ->
            val e = zf.getEntry(MANIFEST) ?: throw IllegalArgumentException("This file has no AndroidManifest.xml. Is it an APK?")
            val bytes = zf.getInputStream(e).use { it.readBytes() }
            return AxmlPatcher.inspect(bytes)
        }
    }

    /** Patches the manifest, aligns the zip, signs it. Returns what was changed. */
    fun build(input: File, output: File, newPkg: String, newLabel: String, key: SigningKey, mode: String = "all"): PatchCounts {
        val unsigned = File(output.parentFile, output.name + ".unsigned")
        unsigned.delete()
        output.delete()
        val counts: PatchCounts
        try {
            val manifest = ZipFile(input).use { zf ->
                val e = zf.getEntry(MANIFEST) ?: throw IllegalArgumentException("This file has no AndroidManifest.xml. Is it an APK?")
                zf.getInputStream(e).use { it.readBytes() }
            }
            val res = AxmlPatcher.patch(manifest, newPkg, newLabel)
            counts = res.counts
            alignCopy(input, res.bytes, unsigned)
            if (mode == "unsigned") {
                unsigned.copyTo(output, overwrite = true)
            } else {
                sign(unsigned, output, key, mode)
                check(output)
            }
        } finally {
            unsigned.delete()
        }
        val fp = MessageDigest.getInstance("SHA-256").digest(key.certificate.encoded)
            .take(4).joinToString("") { "%02x".format(it) }
        counts.note = if (mode == "unsigned") "Aligned but NOT signed. Sign it yourself before installing."
        else "Aligned and signed (" + schemes(mode) + ") with the " + key.source + " key (cert " + fp + ")."
        val bad = checkAlignment(output)
        if (bad != null) {
            counts.warn = true
            counts.note += " WARNING: zip alignment problem: " + bad
        }
        return counts
    }

    // ---------------- zip helpers ----------------
    private fun u16(b: ByteArray, o: Int) = (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8)
    private fun u32(b: ByteArray, o: Int) = u16(b, o).toLong() or (u16(b, o + 2).toLong() shl 16)
    private fun p16(b: ByteArray, o: Int, v: Int) { b[o] = v.toByte(); b[o + 1] = (v shr 8).toByte() }
    private fun p32(b: ByteArray, o: Int, v: Long) {
        b[o] = v.toByte(); b[o + 1] = (v shr 8).toByte(); b[o + 2] = (v shr 16).toByte(); b[o + 3] = (v shr 24).toByte()
    }

    private class CdEntry(val rec: ByteArray, val name: String, val method: Int, val csize: Long, val lfhOff: Long)

    private class Counting(private val o: OutputStream) : OutputStream() {
        var count = 0L
        override fun write(b: Int) { o.write(b); count++ }
        override fun write(b: ByteArray, off: Int, len: Int) { o.write(b, off, len); count += len }
        override fun flush() = o.flush()
        override fun close() = o.close()
    }

    private fun readCentralDirectory(f: RandomAccessFile): List<CdEntry> {
        val len = f.length()
        val tailLen = minOf(len, 70000L).toInt()
        val tail = ByteArray(tailLen)
        f.seek(len - tailLen)
        f.readFully(tail)
        var e = tailLen - 22
        while (e >= 0 && u32(tail, e) != 0x06054b50L) e--
        if (e < 0) throw IllegalArgumentException("This file is not a zip/APK")
        val count = u16(tail, e + 10)
        val cdSize = u32(tail, e + 12)
        val cdOff = u32(tail, e + 16)
        if (count == 0xFFFF || cdSize == 0xFFFFFFFFL || cdOff == 0xFFFFFFFFL) throw IllegalArgumentException("Zip64 files are not supported")
        val cd = ByteArray(cdSize.toInt())
        f.seek(cdOff)
        f.readFully(cd)
        val list = ArrayList<CdEntry>(count)
        var p = 0
        for (i in 0 until count) {
            if (u32(cd, p) != 0x02014b50L) throw IllegalArgumentException("Damaged zip directory")
            val nl = u16(cd, p + 28)
            val el = u16(cd, p + 30)
            val cl = u16(cd, p + 32)
            val total = 46 + nl + el + cl
            list.add(
                CdEntry(
                    cd.copyOfRange(p, p + total),
                    String(cd, p + 46, nl, Charsets.UTF_8),
                    u16(cd, p + 10),
                    u32(cd, p + 20),
                    u32(cd, p + 42)
                )
            )
            p += total
        }
        return list
    }

    private fun isOldSignature(name: String): Boolean {
        val n = name.uppercase()
        if (!n.startsWith("META-INF/")) return false
        if (n == "META-INF/MANIFEST.MF") return true
        val rest = n.substring(9)
        if (rest.contains('/')) return false
        return rest.endsWith(".SF") || rest.endsWith(".RSA") || rest.endsWith(".DSA") || rest.endsWith(".EC")
    }

    /** zipalign padding as an extra field, so the data of a stored entry starts on [align]. */
    private fun padding(dataStart: Long, align: Int): ByteArray {
        var pad = ((align - (dataStart % align)) % align).toInt()
        if (pad in 1..3) pad += align
        if (pad == 0) return ByteArray(0)
        val x = ByteArray(pad)
        x[0] = 0x35; x[1] = 0xD9.toByte()
        p16(x, 2, pad - 4)
        return x
    }

    /**
     * Rewrites the zip like zipalign does: every entry is copied byte for byte (no recompression, data
     * descriptors kept), old signature files are dropped, the manifest is replaced, and stored entries
     * are aligned (4 bytes, native libraries to 16 KB).
     */
    private fun alignCopy(src: File, manifest: ByteArray, target: File) {
        RandomAccessFile(src, "r").use { f ->
            val entries = readCentralDirectory(f)
            val out = Counting(BufferedOutputStream(FileOutputStream(target), 1 shl 16))
            val newCd = ByteArrayOutputStream()
            val buf = ByteArray(1 shl 16)
            var count = 0
            out.use {
                for (e in entries) {
                    if (e.name.endsWith("/") || isOldSignature(e.name)) continue
                    val rec = e.rec.copyOf()
                    val newOff = out.count
                    val nameBytes = e.name.toByteArray(Charsets.UTF_8)
                    if (e.name == MANIFEST) {
                        val crc = CRC32().also { it.update(manifest) }.value
                        val bos = ByteArrayOutputStream()
                        val def = Deflater(Deflater.DEFAULT_COMPRESSION, true)
                        DeflaterOutputStream(bos, def).use { it.write(manifest) }
                        def.end()
                        val comp = bos.toByteArray()
                        val h = ByteArray(30)
                        p32(h, 0, 0x04034b50L)
                        p16(h, 4, 20)
                        p16(h, 6, u16(rec, 8) and 0x0800)       // keep only the UTF-8 name flag
                        p16(h, 8, 8)
                        p16(h, 10, u16(rec, 12))                // time
                        p16(h, 12, u16(rec, 14))                // date
                        p32(h, 14, crc)
                        p32(h, 18, comp.size.toLong())
                        p32(h, 22, manifest.size.toLong())
                        p16(h, 26, nameBytes.size)
                        p16(h, 28, 0)
                        out.write(h); out.write(nameBytes); out.write(comp)
                        p16(rec, 8, u16(rec, 8) and 0x0800)
                        p16(rec, 10, 8)
                        p32(rec, 16, crc)
                        p32(rec, 20, comp.size.toLong())
                        p32(rec, 24, manifest.size.toLong())
                    } else {
                        val lfh = ByteArray(30)
                        f.seek(e.lfhOff)
                        f.readFully(lfh)
                        if (u32(lfh, 0) != 0x04034b50L) throw IllegalArgumentException("Damaged entry " + e.name)
                        val flags = u16(lfh, 6)
                        val oldExtra = u16(lfh, 28)
                        val dataPos = e.lfhOff + 30 + u16(lfh, 26) + oldExtra
                        val extra = if (e.method == 0) {
                            padding(newOff + 30 + nameBytes.size, if (e.name.endsWith(".so")) 16384 else 4)
                        } else ByteArray(0)
                        p16(lfh, 26, nameBytes.size)
                        p16(lfh, 28, extra.size)
                        out.write(lfh); out.write(nameBytes); out.write(extra)
                        // the data
                        f.seek(dataPos)
                        var left = e.csize
                        while (left > 0) {
                            val n = f.read(buf, 0, minOf(buf.size.toLong(), left).toInt())
                            if (n < 0) throw IllegalArgumentException("Unexpected end of file in " + e.name)
                            out.write(buf, 0, n)
                            left -= n
                        }
                        // data descriptor, if the entry has one
                        if (flags and 8 != 0) {
                            val sig = ByteArray(4)
                            f.readFully(sig)
                            val withSig = u32(sig, 0) == 0x08074b50L
                            val dd = ByteArray(if (withSig) 16 else 12)
                            if (withSig) System.arraycopy(sig, 0, dd, 0, 4) else System.arraycopy(sig, 0, dd, 0, 4)
                            f.readFully(dd, 4, dd.size - 4)
                            out.write(dd)
                        }
                    }
                    p32(rec, 42, newOff)
                    newCd.write(rec)
                    count++
                }
                val cdOff = out.count
                val cdBytes = newCd.toByteArray()
                out.write(cdBytes)
                val eocd = ByteArray(22)
                p32(eocd, 0, 0x06054b50L)
                p16(eocd, 8, count)
                p16(eocd, 10, count)
                p32(eocd, 12, cdBytes.size.toLong())
                p32(eocd, 16, cdOff)
                out.write(eocd)
            }
        }
    }

    // ---------------- checks ----------------
    /** Looks at the finished zip the way the installer does: stored entries must start on an aligned offset. */
    fun checkAlignment(apk: File): String? {
        try {
            RandomAccessFile(apk, "r").use { f ->
                val lfh = ByteArray(30)
                for (e in readCentralDirectory(f)) {
                    if (e.method == 0 && !e.name.endsWith("/")) {
                        f.seek(e.lfhOff)
                        f.readFully(lfh)
                        val data = e.lfhOff + 30 + u16(lfh, 26) + u16(lfh, 28)
                        val need = if (e.name.endsWith(".so")) 4096L else 4L
                        if (data % need != 0L) return e.name + " starts at " + data
                    }
                }
            }
        } catch (ex: Exception) {
            return "could not check (" + ex.javaClass.simpleName + ")"
        }
        return null
    }

    /** Runs Android's own signature check on the finished file, so a bad APK is caught before you save it. */
    private fun check(apk: File) {
        val r = ApkVerifier.Builder(apk).build().verify()
        if (!r.isVerified || !(r.isVerifiedUsingV2Scheme || r.isVerifiedUsingV3Scheme)) {
            val why = r.errors.joinToString("; ") { it.toString() }.take(300)
            throw IllegalStateException("The signed APK failed its own check. " + why)
        }
    }

    private fun schemes(mode: String) = when (mode) {
        "v12" -> "v1+v2"
        else -> "v1+v2+v3"
    }

    private fun sign(unsigned: File, output: File, key: SigningKey, mode: String) {
        val cfg = ApkSigner.SignerConfig.Builder("cloner", key.privateKey, listOf(key.certificate)).build()
        // v4 is a separate .idsig file that no installer needs, so it stays off.
        val b = ApkSigner.Builder(listOf(cfg))
            .setInputApk(unsigned)
            .setOutputApk(output)
            .setCreatedBy("Cloner")
            .setV1SigningEnabled(true)
            .setV2SigningEnabled(true)
            .setV3SigningEnabled(mode != "v12")
            .setV4SigningEnabled(false)
        b.build().sign()
    }
}
