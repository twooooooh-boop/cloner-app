package com.example.emptyviewsactivity

import com.android.apksig.ApkSigner
import com.android.apksig.ApkVerifier
import java.io.BufferedOutputStream
import java.io.File
import java.io.FileOutputStream
import java.io.FilterOutputStream
import java.io.OutputStream
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
            .setV3SigningEnabled(true)
            .setV4SigningEnabled(false)
            .build()
            .sign()
    }
}
