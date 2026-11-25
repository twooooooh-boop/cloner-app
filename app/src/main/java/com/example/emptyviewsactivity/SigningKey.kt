package com.example.emptyviewsactivity

import java.io.ByteArrayInputStream
import java.io.File
import java.math.BigInteger
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import java.security.spec.PKCS8EncodedKeySpec

class SigningKey(val privateKey: PrivateKey, val certificate: X509Certificate, val source: String = "stored")

/**
 * One key signs every clone you build, so a clone can update over the previous one.
 */
object SigningKeys {
    /**
     * Uses the key shipped inside the app (signing/cloner-key.pk8 and signing/cloner-cert.der in assets)
     * when [asset] can open it, so the signature never changes between installs.
     * Falls back to a key kept in [dir], created on first use.
     */
    fun loadOrCreate(dir: File, asset: ((String) -> java.io.InputStream)? = null): SigningKey {
        if (asset != null) {
            try {
                val k = asset("signing/cloner-key.pk8").use { it.readBytes() }
                val c = asset("signing/cloner-cert.der").use { it.readBytes() }
                val key = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(k))
                return SigningKey(key, parseCert(c), "bundled")
            } catch (e: Exception) {
                // no bundled key: use the stored one below
            }
        }
        dir.mkdirs()
        val keyFile = File(dir, "cloner-key.pk8")
        val certFile = File(dir, "cloner-cert.der")
        if (keyFile.exists() && certFile.exists()) {
            try {
                val key = KeyFactory.getInstance("RSA").generatePrivate(PKCS8EncodedKeySpec(keyFile.readBytes()))
                val cert = parseCert(certFile.readBytes())
                return SigningKey(key, cert)
            } catch (e: Exception) {
                // damaged files: fall through and make a new key
            }
        }
        val gen = KeyPairGenerator.getInstance("RSA")
        gen.initialize(2048)
        val pair = gen.generateKeyPair()
        val der = selfSignedCert(pair.private, pair.public.encoded)
        val cert = parseCert(der)
        keyFile.writeBytes(pair.private.encoded)
        certFile.writeBytes(der)
        return SigningKey(pair.private, cert, "generated")
    }

    private fun parseCert(der: ByteArray): X509Certificate =
        CertificateFactory.getInstance("X.509").generateCertificate(ByteArrayInputStream(der)) as X509Certificate

    // ---- tiny DER writer, just enough for one self-signed certificate ----
    private fun der(tag: Int, body: ByteArray): ByteArray {
        val n = body.size
        val len = when {
            n < 0x80 -> byteArrayOf(n.toByte())
            n < 0x100 -> byteArrayOf(0x81.toByte(), n.toByte())
            else -> byteArrayOf(0x82.toByte(), (n shr 8).toByte(), n.toByte())
        }
        return byteArrayOf(tag.toByte()) + len + body
    }

    private fun seq(vararg parts: ByteArray): ByteArray = der(0x30, parts.reduce { x, y -> x + y })

    private fun selfSignedCert(priv: PrivateKey, spki: ByteArray): ByteArray {
        val sigAlg = seq(
            der(0x06, byteArrayOf(0x2A, 0x86.toByte(), 0x48, 0x86.toByte(), 0xF7.toByte(), 0x0D, 0x01, 0x01, 0x0B)),
            der(0x05, ByteArray(0))
        )
        val name = seq(
            der(0x31, seq(der(0x06, byteArrayOf(0x55, 0x04, 0x03)), der(0x0C, "Cloner".toByteArray(Charsets.UTF_8))))
        )
        val validity = seq(
            der(0x17, "200101000000Z".toByteArray(Charsets.US_ASCII)),
            der(0x17, "491231235959Z".toByteArray(Charsets.US_ASCII))
        )
        val serial = BigInteger(120, SecureRandom()).add(BigInteger.ONE)
        val tbs = seq(
            der(0xA0, der(0x02, byteArrayOf(2))),
            der(0x02, serial.toByteArray()),
            sigAlg,
            name,
            validity,
            name,
            spki
        )
        val s = Signature.getInstance("SHA256withRSA")
        s.initSign(priv)
        s.update(tbs)
        val sig = s.sign()
        return seq(tbs, sigAlg, der(0x03, byteArrayOf(0) + sig))
    }
}
