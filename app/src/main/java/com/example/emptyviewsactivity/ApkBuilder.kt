package com.example.emptyviewsactivity

import com.android.apksig.ApkSigner
import com.android.apksig.ApkVerifier
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.FilterOutputStream
import java.io.OutputStream
import java.io.RandomAccessFile
import java.security.MessageDigest
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream

object ApkBuilder {
    private const val MANIFEST = "AndroidManifest.xml"

    fun inspect(apk: File): ManifestInfo {
        ZipFile(apk).use { zf ->
            val e = zf.getEntry(MANIFEST) ?: throw IllegalArgumentException("This file has no AndroidManifest.xml. Is it an APK?")
            val bytes = zf.getInputStream(e).use { it.readBytes() }
            return AxmlPatcher.inspect(bytes)
        }
    }

    /** Patches the manifest, rewrites the zip, signs it. Returns what was changed. */
    fun build(input: File, output: File, newPkg: String, newLabel: String, key: SigningKey): PatchCounts {
        val unsigned = File(output.parentFile, output.name + ".unsigned")
        unsigned.delete()
        output.delete()
        val counts: PatchCounts
        try {
            ZipFile(input).use { zf ->
                val e = zf.getEntry(MANIFEST) ?: throw IllegalArgumentException("This file has no AndroidManifest.xml. Is it an APK?")
                val bytes = zf.getInputStream(e).use { it.readBytes() }
                val res = AxmlPatcher.patch(bytes, newPkg, newLabel)
                counts = res.counts
                writeAligned(zf, res.bytes, unsigned)
            }
            sign(unsigned, output, key)
            check(output)
        } finally {
            unsigned.delete()
        }
        val fp = MessageDigest.getInstance("SHA-256").digest(key.certificate.encoded)
            .take(4).joinToString("") { "%02x".format(it) }
        counts.note = "Signed v1+v2 with the " + key.source + " key (cert " + fp + ")."
        val bad = checkAlignment(output)
        if (bad != null) {
            counts.warn = true
            counts.note += " WARNING: zip alignment problem: " + bad
        }
        return counts
    }

    private fun isOldSignature(name: String): Boolean {
        val n = name.uppercase()
        if (!n.startsWith("META-INF/")) return false
        if (n == "META-INF/MANIFEST.MF") return true
        val rest = n.substring(9)
        if (rest.contains('/')) return false
        return rest.endsWith(".SF") || rest.endsWith(".RSA") || rest.endsWith(".DSA") || rest.endsWith(".EC")
    }

    private class CountingOut(out: OutputStream) : FilterOutputStream(out) {
        var count = 0L
        override fun write(b: Int) { out.write(b); count++ }
        override fun write(b: ByteArray, off: Int, len: Int) { out.write(b, off, len); count += len }
    }

    /**
     * Copies every entry except the old signature files, swaps in the new manifest, and keeps
     * stored (uncompressed) entries aligned the way zipalign does, which Android needs for
     * resources.arsc and for native libraries.
     */
    private fun writeAligned(zf: ZipFile, manifest: ByteArray, target: File) {
        val counter = CountingOut(BufferedOutputStream(FileOutputStream(target), 1 shl 16))
        ZipOutputStream(counter).use { zos ->
            val buf = ByteArray(1 shl 16)
            val entries = zf.entries()
            while (entries.hasMoreElements()) {
                val e = entries.nextElement()
                val name = e.name
                if (e.isDirectory || isOldSignature(name)) continue

                if (name == MANIFEST) {
                    val ze = ZipEntry(name)
                    ze.method = ZipEntry.DEFLATED
                    zos.putNextEntry(ze)
                    zos.write(manifest)
                    zos.closeEntry()
                    continue
                }

                if (e.method == ZipEntry.STORED) {
                    val ze = ZipEntry(name)
                    ze.method = ZipEntry.STORED
                    ze.size = e.size
                    ze.compressedSize = e.size
                    ze.crc = e.crc
                    val align = if (name.endsWith(".so")) 16384 else 4
                    val dataStart = counter.count + 30 + name.toByteArray(Charsets.UTF_8).size
                    var pad = ((align - (dataStart % align)) % align).toInt()
                    if (pad in 1..3) pad += align
                    if (pad > 0) {
                        val extra = ByteArray(pad)
                        extra[0] = 0x35; extra[1] = 0xD9.toByte() // zipalign padding record
                        extra[2] = ((pad - 4) and 0xFF).toByte()
                        extra[3] = (((pad - 4) shr 8) and 0xFF).toByte()
                        ze.extra = extra
                    }
                    zos.putNextEntry(ze)
                } else {
                    val ze = ZipEntry(name)
                    ze.method = ZipEntry.DEFLATED
                    zos.putNextEntry(ze)
                }
                zf.getInputStream(e).use { ins ->
                    while (true) {
                        val n = ins.read(buf)
                        if (n < 0) break
                        zos.write(buf, 0, n)
                    }
                }
                zos.closeEntry()
            }
        }
    }

    /** Looks at the finished zip the way the installer does: stored entries must start on an aligned offset. */
    fun checkAlignment(apk: File): String? {
        try {
            RandomAccessFile(apk, "r").use { f ->
                val len = f.length()
                val tailLen = minOf(len, 70000L).toInt()
                val tail = ByteArray(tailLen)
                f.seek(len - tailLen)
                f.readFully(tail)
                var e = tailLen - 22
                while (e >= 0 && !(tail[e] == 0x50.toByte() && tail[e + 1] == 0x4b.toByte() && tail[e + 2] == 0x05.toByte() && tail[e + 3] == 0x06.toByte())) e--
                if (e < 0) return "no end of central directory"
                fun u16(b: ByteArray, o: Int) = (b[o].toInt() and 0xFF) or ((b[o + 1].toInt() and 0xFF) shl 8)
                fun u32(b: ByteArray, o: Int) = u16(b, o).toLong() or (u16(b, o + 2).toLong() shl 16)
                val count = u16(tail, e + 10)
                val cdOff = u32(tail, e + 16)
                val cdSize = u32(tail, e + 12).toInt()
                val cd = ByteArray(cdSize)
                f.seek(cdOff)
                f.readFully(cd)
                var p = 0
                val lfh = ByteArray(30)
                for (i in 0 until count) {
                    if (u32(cd, p) != 0x02014b50L) return "damaged central directory"
                    val method = u16(cd, p + 10)
                    val nl = u16(cd, p + 28)
                    val el = u16(cd, p + 30)
                    val cl = u16(cd, p + 32)
                    val off = u32(cd, p + 42)
                    val name = String(cd, p + 46, nl, Charsets.UTF_8)
                    if (method == 0 && !name.endsWith("/")) {
                        f.seek(off)
                        f.readFully(lfh)
                        val data = off + 30 + u16(lfh, 26) + u16(lfh, 28)
                        val need = if (name.endsWith(".so")) 4096L else 4L
                        if (data % need != 0L) return name + " starts at " + data
                    }
                    p += 46 + nl + el + cl
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

    private fun sign(unsigned: File, output: File, key: SigningKey) {
        val cfg = ApkSigner.SignerConfig.Builder("cloner", key.privateKey, listOf(key.certificate)).build()
        ApkSigner.Builder(listOf(cfg))
            .setInputApk(unsigned)
            .setOutputApk(output)
            .setCreatedBy("Cloner")
            .setV1SigningEnabled(true)
            .setV2SigningEnabled(true)
            .setV3SigningEnabled(false)
            .setV4SigningEnabled(false)
            .build()
            .sign()
    }
}
