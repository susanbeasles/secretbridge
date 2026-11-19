package me.vespoli.secretbridge

import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.charset.StandardCharsets
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.SecureRandom
import java.security.spec.PKCS8EncodedKeySpec
import java.security.spec.X509EncodedKeySpec
import javax.crypto.AEADBadTagException
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/**
 * Pure-JDK-21 implementation of `Noise_IK_25519_ChaChaPoly_BLAKE2s` initiator + chunked framing,
 * wire-compatible byte-for-byte with `sb_proto::crypto::NoiseSession` (`C2`, `H1`).
 *
 * Ensures the JetBrains IDE plugin terminates `Noise_IK` directly with the isolated `sb-enclave`
 * guest process so `sb-host` acts solely as an untrusted raw frame relay.
 */
class NoiseIkSession private constructor(
    private val txCipher: NoiseCipherState,
    private val rxCipher: NoiseCipherState,
    val peerStaticPubkey: ByteArray,
) : AutoCloseable {
    private var txFrames: Long = 0L
    private var rxFrames: Long = 0L

    fun sendMessage(writeRawFrame: (ByteArray) -> Unit, plaintext: ByteArray) {
        if (plaintext.size > MAX_RPC_MESSAGE_BYTES) {
            throw EnclaveBridgeException("size_limit_exceeded", "RPC message exceeds 1 MiB cap")
        }
        if (plaintext.isEmpty()) {
            val chunk = byteArrayOf(0x00)
            val ct = txCipher.encryptWithAd(EMPTY_BYTES, chunk)
            stepTxRekey()
            writeRawFrame(ct)
            return
        }

        var offset = 0
        while (offset < plaintext.size) {
            val len = minOf(PLAINTEXT_CHUNK_BYTES, plaintext.size - offset)
            val hasMore = (offset + len) < plaintext.size
            val chunkPlain = ByteArray(len + 1)
            try {
                chunkPlain[0] = if (hasMore) 0x01 else 0x00
                System.arraycopy(plaintext, offset, chunkPlain, 1, len)
                val ct = txCipher.encryptWithAd(EMPTY_BYTES, chunkPlain)
                stepTxRekey()
                writeRawFrame(ct)
            } finally {
                chunkPlain.fill(0)
            }
            offset += len
        }
    }

    fun recvMessage(readRawFrame: () -> ByteArray): ByteArray {
        val chunks = ArrayList<ByteArray>()
        var totalLen = 0
        var chunkCount = 0

        try {
            while (true) {
                chunkCount += 1
                if (chunkCount > MAX_CHUNKS_PER_MESSAGE) {
                    throw EnclaveBridgeException("transport_failure", "Noise message exceeded maximum chunk count")
                }
                val ct = readRawFrame()
                val dec = rxCipher.decryptWithAd(EMPTY_BYTES, ct)
                stepRxRekey()
                if (dec.isEmpty()) {
                    throw EnclaveBridgeException("transport_failure", "Empty Noise chunk")
                }
                val more = dec[0].toInt() and 0xFF
                val payloadLen = dec.size - 1
                if (more == 0x01 && payloadLen == 0) {
                    dec.fill(0)
                    throw EnclaveBridgeException("transport_failure", "Empty continuation Noise chunk rejected")
                }
                if (totalLen + payloadLen > MAX_RPC_MESSAGE_BYTES) {
                    dec.fill(0)
                    throw EnclaveBridgeException("size_limit_exceeded", "Assembled RPC message exceeds 1 MiB cap")
                }
                val part = dec.copyOfRange(1, dec.size)
                dec.fill(0)
                chunks.add(part)
                totalLen += part.size

                when (more) {
                    0x00 -> {
                        val assembled = ByteArray(totalLen)
                        var pos = 0
                        for (c in chunks) {
                            System.arraycopy(c, 0, assembled, pos, c.size)
                            pos += c.size
                            c.fill(0)
                        }
                        chunks.clear()
                        return assembled
                    }
                    0x01 -> continue
                    else -> throw EnclaveBridgeException("transport_failure", "Invalid Noise chunk continuation flag")
                }
            }
        } catch (t: Throwable) {
            for (c in chunks) {
                c.fill(0)
            }
            throw t
        }
    }

    private fun stepTxRekey() {
        txFrames += 1L
        if (txFrames % REKEY_FRAME_INTERVAL == 0L) {
            txCipher.rekey()
        }
    }

    private fun stepRxRekey() {
        rxFrames += 1L
        if (rxFrames % REKEY_FRAME_INTERVAL == 0L) {
            rxCipher.rekey()
        }
    }

    override fun close() {
        txCipher.wipe()
        rxCipher.wipe()
    }

    companion object {
        const val NOISE_PATTERN = "Noise_IK_25519_ChaChaPoly_BLAKE2s"
        const val MAX_RPC_MESSAGE_BYTES = 1024 * 1024
        const val MAX_WIRE_FRAME_BYTES = 65_535
        private const val PLAINTEXT_CHUNK_BYTES = 60_000
        private const val MAX_CHUNKS_PER_MESSAGE = (MAX_RPC_MESSAGE_BYTES / PLAINTEXT_CHUNK_BYTES) + 2
        private const val REKEY_FRAME_INTERVAL = 1_024L
        private val EMPTY_BYTES = ByteArray(0)

        // RFC 8410 ASN.1 DER prefixes for 32-byte X25519 public (X.509) and private (PKCS#8) keys
        private val X509_X25519_PREFIX = byteArrayOf(
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x03, 0x21, 0x00,
        )
        private val PKCS8_X25519_PREFIX = byteArrayOf(
            0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x6E, 0x04, 0x22, 0x04, 0x20,
        )
        private val X25519_BASEPOINT = ByteArray(32).apply { this[0] = 9 }
        private val SECURE_RANDOM = SecureRandom()

        fun generateStaticKeypair(): Pair<ByteArray, ByteArray> {
            val priv = ByteArray(32)
            SECURE_RANDOM.nextBytes(priv)
            return try {
                val pub = derivePublicKey(priv)
                priv to pub
            } catch (t: Throwable) {
                priv.fill(0)
                throw t
            }
        }

        fun derivePublicKey(privateKey32: ByteArray): ByteArray {
            require(privateKey32.size == 32) { "X25519 private key must be 32 bytes" }
            return x25519Dh(privateKey32, X25519_BASEPOINT)
        }

        fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean = MessageDigest.isEqual(a, b)

        fun connectInitiator(
            writeRawFrame: (ByteArray) -> Unit,
            readRawFrame: () -> ByteArray,
            clientPrivate32: ByteArray,
            expectedEnclavePubkey32: ByteArray,
        ): NoiseIkSession {
            require(clientPrivate32.size == 32) { "Client Noise private key must be 32 bytes" }
            require(expectedEnclavePubkey32.size == 32) { "Enclave Noise public key must be 32 bytes" }

            val clientPub32 = derivePublicKey(clientPrivate32)
            val protocolBytes = NOISE_PATTERN.toByteArray(StandardCharsets.US_ASCII)
            var h = Blake2s256.hash(protocolBytes)
            var ck = h.copyOf()
            val hsCipher = NoiseCipherState()

            // MixHash(prologue = "")
            h = mixHash(h, EMPTY_BYTES)
            // Pre-message `<- s`: MixHash(rs)
            h = mixHash(h, expectedEnclavePubkey32)

            val (ephPriv, ephPub) = generateStaticKeypair()
            try {
                // Message 1: `-> e, es, s, ss` + empty payload
                val msg1 = ByteArray(96)
                System.arraycopy(ephPub, 0, msg1, 0, 32)
                h = mixHash(h, ephPub)

                val dhEs = x25519Dh(ephPriv, expectedEnclavePubkey32)
                ck = mixKey(ck, dhEs, hsCipher)

                val encStatic = hsCipher.encryptWithAd(h, clientPub32)
                System.arraycopy(encStatic, 0, msg1, 32, 48)
                h = mixHash(h, encStatic)

                val dhSs = x25519Dh(clientPrivate32, expectedEnclavePubkey32)
                ck = mixKey(ck, dhSs, hsCipher)

                val encPayload1 = hsCipher.encryptWithAd(h, EMPTY_BYTES)
                System.arraycopy(encPayload1, 0, msg1, 80, 16)
                h = mixHash(h, encPayload1)

                writeRawFrame(msg1)

                // Message 2: `<- e, ee, se` + responder payload
                val msg2 = readRawFrame()
                if (msg2.size < 48) {
                    throw EnclaveBridgeException(
                        "unauthorized",
                        "Enclave Noise_IK responder handshake frame too short",
                    )
                }
                val rePub = msg2.copyOfRange(0, 32)
                h = mixHash(h, rePub)

                val dhEe = x25519Dh(ephPriv, rePub)
                ck = mixKey(ck, dhEe, hsCipher)

                val dhSe = x25519Dh(clientPrivate32, rePub)
                ck = mixKey(ck, dhSe, hsCipher)

                val ctPayload2 = msg2.copyOfRange(32, msg2.size)
                val plainPayload2 = hsCipher.decryptWithAd(h, ctPayload2)
                plainPayload2.fill(0)
                h = mixHash(h, ctPayload2)

                val (k1, k2) = hkdf2(ck, EMPTY_BYTES)
                val tx = NoiseCipherState().apply { initializeKey(k1) }
                val rx = NoiseCipherState().apply { initializeKey(k2) }
                k1.fill(0)
                k2.fill(0)
                return NoiseIkSession(tx, rx, expectedEnclavePubkey32.copyOf())
            } finally {
                ephPriv.fill(0)
                hsCipher.wipe()
                ck.fill(0)
                h.fill(0)
            }
        }

        private fun mixHash(h: ByteArray, data: ByteArray): ByteArray {
            val next = Blake2s256.hashTwo(h, data)
            h.fill(0)
            return next
        }

        private fun mixKey(ck: ByteArray, ikm: ByteArray, cipher: NoiseCipherState): ByteArray {
            return try {
                val (nextCk, tempK) = hkdf2(ck, ikm)
                ck.fill(0)
                cipher.initializeKey(tempK)
                tempK.fill(0)
                nextCk
            } finally {
                ikm.fill(0)
            }
        }

        internal fun hkdf2(chainingKey: ByteArray, ikm: ByteArray): Pair<ByteArray, ByteArray> {
            val tempKey = Blake2s256.hmac(chainingKey, ikm)
            return try {
                val out1 = Blake2s256.hmac(tempKey, byteArrayOf(0x01))
                val out2Input = ByteArray(out1.size + 1)
                System.arraycopy(out1, 0, out2Input, 0, out1.size)
                out2Input[out1.size] = 0x02
                val out2 = try {
                    Blake2s256.hmac(tempKey, out2Input)
                } finally {
                    out2Input.fill(0)
                }
                out1 to out2
            } finally {
                tempKey.fill(0)
            }
        }

        private fun x25519Dh(priv32: ByteArray, pub32: ByteArray): ByteArray {
            val pkcs8 = ByteArray(PKCS8_X25519_PREFIX.size + 32)
            val x509 = ByteArray(X509_X25519_PREFIX.size + 32)
            System.arraycopy(PKCS8_X25519_PREFIX, 0, pkcs8, 0, PKCS8_X25519_PREFIX.size)
            System.arraycopy(priv32, 0, pkcs8, PKCS8_X25519_PREFIX.size, 32)
            System.arraycopy(X509_X25519_PREFIX, 0, x509, 0, X509_X25519_PREFIX.size)
            System.arraycopy(pub32, 0, x509, X509_X25519_PREFIX.size, 32)
            return try {
                val kf = try {
                    KeyFactory.getInstance("X25519", "SunEC")
                } catch (_: Exception) {
                    KeyFactory.getInstance("X25519")
                }
                val privKey = kf.generatePrivate(PKCS8EncodedKeySpec(pkcs8))
                val pubKey = kf.generatePublic(X509EncodedKeySpec(x509))
                val ka = try {
                    KeyAgreement.getInstance("X25519", "SunEC")
                } catch (_: Exception) {
                    KeyAgreement.getInstance("X25519")
                }
                ka.init(privKey)
                ka.doPhase(pubKey, true)
                ka.generateSecret()
            } catch (e: Exception) {
                throw EnclaveBridgeException("unauthorized", "X25519 key agreement rejected peer key: ${e.message}")
            } finally {
                pkcs8.fill(0)
                x509.fill(0)
            }
        }
    }
}

private class NoiseCipherState {
    private val key = ByteArray(32)
    private var hasKey = false
    private var nonce: Long = 0L

    fun initializeKey(newKey32: ByteArray) {
        require(newKey32.size == 32)
        System.arraycopy(newKey32, 0, key, 0, 32)
        hasKey = true
        nonce = 0L
    }

    fun encryptWithAd(ad: ByteArray, plaintext: ByteArray): ByteArray {
        if (!hasKey) return plaintext.copyOf()
        if (nonce == -1L) {
            throw EnclaveBridgeException("crypto_failure", "Noise ChaChaPoly nonce exhausted")
        }
        val ct = chachaPolySeal(key, nonce, ad, plaintext)
        nonce += 1L
        return ct
    }

    fun decryptWithAd(ad: ByteArray, ciphertext: ByteArray): ByteArray {
        if (!hasKey) return ciphertext.copyOf()
        if (nonce == -1L) {
            throw EnclaveBridgeException("crypto_failure", "Noise ChaChaPoly nonce exhausted")
        }
        val pt = chachaPolyOpen(key, nonce, ad, ciphertext)
        nonce += 1L
        return pt
    }

    fun rekey() {
        check(hasKey) { "Cannot rekey uninitialized NoiseCipherState" }
        val zeros = ByteArray(32)
        val block = chachaPolySeal(key, -1L, ByteArray(0), zeros)
        try {
            System.arraycopy(block, 0, key, 0, 32)
        } finally {
            block.fill(0)
        }
    }

    fun wipe() {
        key.fill(0)
        hasKey = false
        nonce = 0L
    }

    companion object {
        private fun makeNoiseIv(n: Long): ByteArray {
            val iv = ByteArray(12)
            ByteBuffer.wrap(iv, 4, 8).order(ByteOrder.LITTLE_ENDIAN).putLong(n)
            return iv
        }

        private fun chachaPolySeal(key32: ByteArray, nonce: Long, ad: ByteArray, plaintext: ByteArray): ByteArray {
            val iv = makeNoiseIv(nonce)
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key32, "ChaCha20"), IvParameterSpec(iv))
            if (ad.isNotEmpty()) {
                cipher.updateAAD(ad)
            }
            return cipher.doFinal(plaintext)
        }

        private fun chachaPolyOpen(key32: ByteArray, nonce: Long, ad: ByteArray, ciphertext: ByteArray): ByteArray {
            val iv = makeNoiseIv(nonce)
            val cipher = Cipher.getInstance("ChaCha20-Poly1305")
            cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(key32, "ChaCha20"), IvParameterSpec(iv))
            if (ad.isNotEmpty()) {
                cipher.updateAAD(ad)
            }
            return try {
                cipher.doFinal(ciphertext)
            } catch (_: AEADBadTagException) {
                throw EnclaveBridgeException("unauthorized", "Noise_IK ChaCha20-Poly1305 authentication failed")
            } catch (e: Exception) {
                throw EnclaveBridgeException("crypto_failure", "Noise_IK decryption failed: ${e.message}")
            }
        }
    }
}

/**
 * Pure-Kotlin RFC 7693 `BLAKE2s-256` & `HMAC-BLAKE2s` implementation (zero third-party dependencies).
 */
internal object Blake2s256 {
    private const val BLOCK_BYTES = 64
    private val IV = intArrayOf(
        0x6A09E667,
        -0x4498517B, // 0xBB67AE85
        0x3C6EF372,
        -0x5AB00AC6, // 0xA54FF53A
        0x510E527F,
        -0x64FA9774, // 0x9B05688C
        0x1F83D9AB,
        0x5BE0CD19,
    )

    private val SIGMA = arrayOf(
        intArrayOf(0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15),
        intArrayOf(14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3),
        intArrayOf(11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4),
        intArrayOf(7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8),
        intArrayOf(9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13),
        intArrayOf(2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9),
        intArrayOf(12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11),
        intArrayOf(13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10),
        intArrayOf(6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5),
        intArrayOf(10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0),
    )

    fun hash(input: ByteArray): ByteArray {
        val h = IV.copyOf()
        h[0] = h[0] xor 0x01010020

        val block = ByteArray(BLOCK_BYTES)
        if (input.isEmpty()) {
            compress(h, block, 0L, isLast = true)
        } else {
            var offset = 0
            while (input.size - offset > BLOCK_BYTES) {
                System.arraycopy(input, offset, block, 0, BLOCK_BYTES)
                offset += BLOCK_BYTES
                compress(h, block, offset.toLong(), isLast = false)
            }
            block.fill(0)
            val rem = input.size - offset
            System.arraycopy(input, offset, block, 0, rem)
            compress(h, block, input.size.toLong(), isLast = true)
            block.fill(0)
        }

        val out = ByteArray(32)
        val bb = ByteBuffer.wrap(out).order(ByteOrder.LITTLE_ENDIAN)
        for (word in h) {
            bb.putInt(word)
        }
        return out
    }

    fun hashTwo(first: ByteArray, second: ByteArray): ByteArray {
        val combined = ByteArray(first.size + second.size)
        return try {
            System.arraycopy(first, 0, combined, 0, first.size)
            System.arraycopy(second, 0, combined, first.size, second.size)
            hash(combined)
        } finally {
            combined.fill(0)
        }
    }

    fun hmac(key: ByteArray, message: ByteArray): ByteArray {
        val normalizedKey = if (key.size > BLOCK_BYTES) hash(key) else key.copyOf()
        val ipad = ByteArray(BLOCK_BYTES)
        val opad = ByteArray(BLOCK_BYTES)
        return try {
            for (i in 0 until BLOCK_BYTES) {
                val kb = if (i < normalizedKey.size) normalizedKey[i].toInt() and 0xFF else 0
                ipad[i] = (kb xor 0x36).toByte()
                opad[i] = (kb xor 0x5C).toByte()
            }
            val inner = hashTwo(ipad, message)
            try {
                hashTwo(opad, inner)
            } finally {
                inner.fill(0)
            }
        } finally {
            normalizedKey.fill(0)
            ipad.fill(0)
            opad.fill(0)
        }
    }

    private fun compress(h: IntArray, block: ByteArray, totalBytes: Long, isLast: Boolean) {
        val m = IntArray(16)
        val bb = ByteBuffer.wrap(block).order(ByteOrder.LITTLE_ENDIAN)
        for (i in 0 until 16) {
            m[i] = bb.getInt()
        }

        val v = IntArray(16)
        System.arraycopy(h, 0, v, 0, 8)
        System.arraycopy(IV, 0, v, 8, 8)
        v[12] = v[12] xor totalBytes.toInt()
        v[13] = v[13] xor (totalBytes ushr 32).toInt()
        if (isLast) {
            v[14] = v[14].inv()
        }

        for (round in 0 until 10) {
            val s = SIGMA[round]
            g(v, 0, 4, 8, 12, m[s[0]], m[s[1]])
            g(v, 1, 5, 9, 13, m[s[2]], m[s[3]])
            g(v, 2, 6, 10, 14, m[s[4]], m[s[5]])
            g(v, 3, 7, 11, 15, m[s[6]], m[s[7]])
            g(v, 0, 5, 10, 15, m[s[8]], m[s[9]])
            g(v, 1, 6, 11, 12, m[s[10]], m[s[11]])
            g(v, 2, 7, 8, 13, m[s[12]], m[s[13]])
            g(v, 3, 4, 9, 14, m[s[14]], m[s[15]])
        }

        for (i in 0 until 8) {
            h[i] = h[i] xor v[i] xor v[i + 8]
        }
        m.fill(0)
        v.fill(0)
    }

    private fun g(v: IntArray, a: Int, b: Int, c: Int, d: Int, x: Int, y: Int) {
        v[a] = v[a] + v[b] + x
        v[d] = (v[d] xor v[a]).rotateRight(16)
        v[c] = v[c] + v[d]
        v[b] = (v[b] xor v[c]).rotateRight(12)
        v[a] = v[a] + v[b] + y
        v[d] = (v[d] xor v[a]).rotateRight(8)
        v[c] = v[c] + v[d]
        v[b] = (v[b] xor v[c]).rotateRight(7)
    }
}
