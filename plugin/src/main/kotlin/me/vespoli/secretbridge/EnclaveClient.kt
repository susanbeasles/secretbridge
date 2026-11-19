package me.vespoli.secretbridge

import com.intellij.openapi.Disposable
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.service
import com.intellij.openapi.progress.ProcessCanceledException
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import java.io.BufferedReader
import java.io.ByteArrayOutputStream
import java.io.InputStream
import java.io.InputStreamReader
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.nio.channels.SelectionKey
import java.nio.channels.Selector
import java.nio.channels.SocketChannel
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.attribute.PosixFilePermissions
import java.util.ArrayDeque
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicReference
import javax.swing.SwingUtilities

data class ParsedHostBanner(
    val socketPath: Path,
    val authTokenChars: CharArray,
    val enclavePubkey32: ByteArray,
)

/**
 * Unix domain socket client speaking authenticated [HostCommand] frames to `sb-host` and
 * terminating end-to-end `Noise_IK_25519_ChaChaPoly_BLAKE2s` sessions directly with `sb-enclave`
 * over [HostCommand.NoiseTunnel] (`C2`, `H8`).
 */
class HostSocketTransport(
    val socketPath: Path,
    authTokenHex: CharArray,
    clientPrivateKey32: ByteArray = ByteArray(0),
    expectedEnclavePubkey32: ByteArray = ByteArray(0),
    private val ioTimeoutMs: Long = DEFAULT_IO_TIMEOUT_MS,
) : AutoCloseable {
    private val tokenChars: CharArray = authTokenHex.copyOf()
    private val clientPrivCopy: ByteArray = clientPrivateKey32.copyOf()
    private val enclavePubCopy: ByteArray = expectedEnclavePubkey32.copyOf()

    @Synchronized
    fun execute(command: HostCommand): HostResponse {
        check(tokenChars.isNotEmpty()) { "HostSocketTransport has already been closed" }
        val envelope = AuthenticatedHostEnvelope(tokenChars, command)
        val requestBytes = JsonCodec.encodeUtf8(envelope.toJson(), appendNewline = true)
        try {
            openTimedUnixChannel(socketPath, ioTimeoutMs).use { io ->
                io.writeFully(requestBytes)
                val responseLine = io.readUtf8Line(MAX_RESPONSE_BYTES)
                if (responseLine.isBlank()) {
                    throw EnclaveBridgeException(
                        "transport_failure",
                        "Empty response received from sb-host Unix socket",
                    )
                }
                val json = JsonCodec.parseObject(responseLine)
                return HostResponse.fromJson(json)
            }
        } finally {
            requestBytes.fill(0)
        }
    }

    /**
     * Opens a blind [HostCommand.NoiseTunnel] through `sb-host`, verifies `enclave_pubkey_hex` in
     * constant time, performs a fresh `Noise_IK` handshake directly with `sb-enclave`, and executes
     * [request] with zero plaintext exposure to `sb-host` (`C2`).
     */
    @Synchronized
    fun executeEnclave(request: EnclaveRequest): EnclaveResult {
        return executeEnclaveBatch(listOf(request)).single()
    }

    @Synchronized
    fun executeEnclaveBatch(requests: List<EnclaveRequest>): List<EnclaveResult> {
        check(tokenChars.isNotEmpty()) { "HostSocketTransport has already been closed" }
        require(
            clientPrivCopy.size == 32 &&
                enclavePubCopy.size == 32 &&
                enclavePubCopy.any { it != 0.toByte() },
        ) {
            "HostSocketTransport requires 32-byte client Noise private key and non-zero pinned enclave public key for E2E tunnel"
        }
        if (requests.isEmpty()) return emptyList()

        val tunnelEnvelope = AuthenticatedHostEnvelope(tokenChars, HostCommand.NoiseTunnel)
        val tunnelBytes = JsonCodec.encodeUtf8(tunnelEnvelope.toJson(), appendNewline = true)
        try {
            openTimedUnixChannel(socketPath, ioTimeoutMs).use { io ->
                io.writeFully(tunnelBytes)
                val readyLine = io.readUtf8Line(MAX_RESPONSE_BYTES)
                if (readyLine.isBlank()) {
                    throw EnclaveBridgeException(
                        "transport_failure",
                        "Empty tunnel handshake response from sb-host",
                    )
                }
                val readyResp = HostResponse.fromJson(JsonCodec.parseObject(readyLine))
                val reportedPubHex = readyResp.requireTunnelEnclavePubkeyHex()
                val reportedPub32 = try {
                    BridgeSettings.decodeHex32(reportedPubHex)
                } catch (_: IllegalArgumentException) {
                    throw EnclaveBridgeException("crypto_failure", "Malformed enclave_pubkey_hex in tunnel response")
                }
                if (!NoiseIkSession.constantTimeEquals(reportedPub32, enclavePubCopy)) {
                    throw EnclaveBridgeException(
                        "unauthorized",
                        "Enclave Noise static public key mismatch on tunnel handshake",
                    )
                }

                NoiseIkSession.connectInitiator(
                    writeRawFrame = io::writeNoiseFrame,
                    readRawFrame = io::readNoiseFrame,
                    clientPrivate32 = clientPrivCopy,
                    expectedEnclavePubkey32 = enclavePubCopy,
                ).use { noise ->
                    val out = ArrayList<EnclaveResult>(requests.size)
                    for (req in requests) {
                        val reqBytes = JsonCodec.encodeUtf8(req.toJson(), appendNewline = false)
                        val respBytes = try {
                            noise.sendMessage(io::writeNoiseFrame, reqBytes)
                            noise.recvMessage(io::readNoiseFrame)
                        } finally {
                            reqBytes.fill(0)
                        }
                        val parsed = try {
                            val respStr = String(respBytes, StandardCharsets.UTF_8)
                            EnclaveResponse.fromJson(JsonCodec.parseObject(respStr))
                        } finally {
                            respBytes.fill(0)
                        }
                        out.add(parsed.requireResult())
                    }
                    return out
                }
            }
        } finally {
            tunnelBytes.fill(0)
        }
    }

    override fun close() {
        tokenChars.fill('\u0000')
        clientPrivCopy.fill(0)
        enclavePubCopy.fill(0)
    }

    companion object {
        private const val MAX_RESPONSE_BYTES = 1024 * 1024
        private const val DEFAULT_IO_TIMEOUT_MS = 45_000L
        private const val SELECT_SLICE_MS = 200L
        private const val BANNER_PREFIX = "SB_HOST_READY "

        /**
         * Parses `SB_HOST_READY token=<64-hex> enckey=<64-hex> socket=<path-with-spaces>` directly
         * from a [CharArray] so paths containing spaces parse cleanly and `token` never becomes a
         * JVM [String] (`H8`).
         */
        fun parseReadyBannerChars(chars: CharArray): ParsedHostBanner {
            var start = 0
            var end = chars.size
            while (start < end && chars[start].isWhitespace()) start++
            while (end > start && chars[end - 1].isWhitespace()) end--

            if (end - start <= BANNER_PREFIX.length || !regionStartsWith(chars, start, end, BANNER_PREFIX)) {
                throw EnclaveBridgeException("transport_failure", "Unexpected sb-host startup banner")
            }
            var cursor = start + BANNER_PREFIX.length
            var tokenChars: CharArray? = null
            var encKeyBytes: ByteArray? = null
            var socketPathStr: String? = null

            while (cursor < end) {
                while (cursor < end && chars[cursor] == ' ') cursor++
                if (cursor >= end) break

                when {
                    regionStartsWith(chars, cursor, end, "socket=") -> {
                        // `socket=` is emitted LAST so the remainder of the trimmed line is the full path
                        // even when the user's home directory contains spaces!
                        val pathStart = cursor + "socket=".length
                        socketPathStr = String(chars, pathStart, end - pathStart).trim()
                        cursor = end
                    }
                    regionStartsWith(chars, cursor, end, "token=") -> {
                        val valStart = cursor + "token=".length
                        var valEnd = valStart
                        while (valEnd < end && chars[valEnd] != ' ') valEnd++
                        tokenChars = chars.copyOfRange(valStart, valEnd)
                        cursor = valEnd
                    }
                    regionStartsWith(chars, cursor, end, "enckey=") -> {
                        val valStart = cursor + "enckey=".length
                        var valEnd = valStart
                        while (valEnd < end && chars[valEnd] != ' ') valEnd++
                        val keyHexChars = chars.copyOfRange(valStart, valEnd)
                        encKeyBytes = try {
                            BridgeSettings.decodeHexChars32OrNull(keyHexChars)
                                ?: throw EnclaveBridgeException(
                                    "transport_failure",
                                    "Invalid 64-hex enckey in SB_HOST_READY",
                                )
                        } finally {
                            keyHexChars.fill('\u0000')
                        }
                        cursor = valEnd
                    }
                    else -> {
                        while (cursor < end && chars[cursor] != ' ') cursor++
                    }
                }
            }

            val resolvedSocket = socketPathStr?.takeIf { it.isNotEmpty() } ?: run {
                tokenChars?.fill('\u0000')
                throw EnclaveBridgeException("transport_failure", "Missing socket path in SB_HOST_READY")
            }
            val resolvedToken = tokenChars?.takeIf {
                it.size == 64 && BridgeSettings.decodeHexChars32OrNull(it)?.also { b -> b.fill(0) } != null
            } ?: run {
                tokenChars?.fill('\u0000')
                throw EnclaveBridgeException("transport_failure", "Invalid 64-hex token in SB_HOST_READY")
            }
            val resolvedEnclaveKey = encKeyBytes ?: ByteArray(32)
            return ParsedHostBanner(Paths.get(resolvedSocket), resolvedToken, resolvedEnclaveKey)
        }

        fun parseReadyBanner(line: String): ParsedHostBanner {
            val chars = line.toCharArray()
            return try {
                parseReadyBannerChars(chars)
            } finally {
                chars.fill('\u0000')
            }
        }

        private fun regionStartsWith(chars: CharArray, offset: Int, limit: Int, prefix: String): Boolean {
            if (offset + prefix.length > limit) return false
            for (i in prefix.indices) {
                if (chars[offset + i] != prefix[i]) return false
            }
            return true
        }

        private fun openTimedUnixChannel(socketPath: Path, timeoutMs: Long): TimedUnixChannel {
            val channel = SocketChannel.open(StandardProtocolFamily.UNIX)
            val selector = Selector.open()
            var ok = false
            try {
                channel.configureBlocking(false)
                val connected = channel.connect(UnixDomainSocketAddress.of(socketPath))
                if (!connected) {
                    val key = channel.register(selector, SelectionKey.OP_CONNECT)
                    val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
                    while (!channel.finishConnect()) {
                        checkIdeCanceled()
                        val remainingMs = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())
                        if (remainingMs <= 0L) {
                            throw EnclaveBridgeException("transport_failure", "Timed out connecting to sb-host socket")
                        }
                        selector.select(minOf(SELECT_SLICE_MS, remainingMs))
                        selector.selectedKeys().clear()
                    }
                    key.interestOps(0)
                }
                ok = true
                return TimedUnixChannel(channel, selector, timeoutMs)
            } finally {
                if (!ok) {
                    try {
                        selector.close()
                    } catch (_: Exception) {
                    }
                    try {
                        channel.close()
                    } catch (_: Exception) {
                    }
                }
            }
        }

        private fun checkIdeCanceled() {
            if (ApplicationManager.getApplication() != null) {
                ProgressManager.checkCanceled()
            }
        }
    }

    private class TimedUnixChannel(
        private val channel: SocketChannel,
        private val selector: Selector,
        private val timeoutMs: Long,
    ) : AutoCloseable {
        private val readBuf = ByteBuffer.allocate(8192).apply { flip() }

        fun writeFully(bytes: ByteArray) {
            val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
            val src = ByteBuffer.wrap(bytes)
            while (src.hasRemaining()) {
                checkIdeCanceled()
                val n = channel.write(src)
                if (n > 0) continue
                waitReady(SelectionKey.OP_WRITE, deadline, "write")
            }
        }

        fun readUtf8Line(maxBytes: Int): String {
            val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
            val out = ByteArrayOutputStream(256)
            while (true) {
                while (readBuf.hasRemaining()) {
                    val b = readBuf.get()
                    if (b == '\n'.code.toByte()) {
                        return String(out.toByteArray(), StandardCharsets.UTF_8)
                    }
                    if (out.size() >= maxBytes) {
                        throw EnclaveBridgeException(
                            "size_limit_exceeded",
                            "sb-host response exceeded maximum frame size",
                        )
                    }
                    out.write(b.toInt() and 0xFF)
                }
                if (!fillReadBuffer(deadline)) {
                    break
                }
            }
            return String(out.toByteArray(), StandardCharsets.UTF_8)
        }

        fun writeNoiseFrame(payload: ByteArray) {
            if (payload.isEmpty() || payload.size > NoiseIkSession.MAX_WIRE_FRAME_BYTES) {
                throw EnclaveBridgeException("transport_failure", "Invalid Noise wire frame size")
            }
            val framed = ByteArray(4 + payload.size)
            try {
                ByteBuffer.wrap(framed, 0, 4).order(ByteOrder.BIG_ENDIAN).putInt(payload.size)
                System.arraycopy(payload, 0, framed, 4, payload.size)
                writeFully(framed)
            } finally {
                framed.fill(0)
            }
        }

        fun readNoiseFrame(): ByteArray {
            val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(timeoutMs)
            val hdr = readExactBytes(4, deadline)
            val len = ByteBuffer.wrap(hdr).order(ByteOrder.BIG_ENDIAN).int
            if (len <= 0 || len > NoiseIkSession.MAX_WIRE_FRAME_BYTES) {
                throw EnclaveBridgeException("transport_failure", "Noise wire frame length out of bounds: $len")
            }
            return readExactBytes(len, deadline)
        }

        private fun readExactBytes(count: Int, deadline: Long): ByteArray {
            val out = ByteArray(count)
            var pos = 0
            while (pos < count) {
                if (readBuf.hasRemaining()) {
                    val take = minOf(count - pos, readBuf.remaining())
                    readBuf.get(out, pos, take)
                    pos += take
                    continue
                }
                if (!fillReadBuffer(deadline)) {
                    throw EnclaveBridgeException("transport_failure", "Unexpected EOF reading Noise_IK frame")
                }
            }
            return out
        }

        private fun fillReadBuffer(deadline: Long): Boolean {
            readBuf.clear()
            while (true) {
                checkIdeCanceled()
                val n = channel.read(readBuf)
                if (n < 0) {
                    readBuf.flip()
                    return false
                }
                if (n > 0) {
                    readBuf.flip()
                    return true
                }
                waitReady(SelectionKey.OP_READ, deadline, "read")
            }
        }

        private fun waitReady(ops: Int, deadline: Long, label: String) {
            val remainingMs = TimeUnit.NANOSECONDS.toMillis(deadline - System.nanoTime())
            if (remainingMs <= 0L) {
                throw EnclaveBridgeException("transport_failure", "Timed out waiting for socket $label")
            }
            val key = channel.keyFor(selector) ?: channel.register(selector, ops)
            key.interestOps(ops)
            selector.select(minOf(SELECT_SLICE_MS, remainingMs))
            selector.selectedKeys().clear()
            key.interestOps(0)
        }

        override fun close() {
            try {
                selector.close()
            } catch (_: Exception) {
            }
            try {
                channel.close()
            } catch (_: Exception) {
            }
        }
    }
}

@Service(Service.Level.PROJECT)
class EnclaveClient(private val project: Project) : Disposable {
    private val lock = Any()
    private var managedProcess: ManagedHostProcess? = null

    fun manifestPathOrNull(): Path? {
        val basePath = project.basePath ?: return null
        return Paths.get(basePath, "secretbridge.json")
    }

    fun requireManifestPath(): String =
        manifestPathOrNull()?.toString()
            ?: throw EnclaveBridgeException("manifest_io", "Project base directory is unavailable")

    fun executeHostCommandOffEdt(command: HostCommand): HostResponse {
        assertOffEdt()
        val session = ensureRunningSession()
        return session.transport.execute(command)
    }

    fun executeEnclaveOffEdt(request: EnclaveRequest): EnclaveResult {
        assertOffEdt()
        val session = ensureRunningSession()
        return session.transport.executeEnclave(request)
    }

    /**
     * Executes the 3-step zero-trust Armed Copy Hijack (`C2`, `H2`):
     * 1. `BeginCapture` over E2E `Noise_IK` -> receives ephemeral `pk_capture_b64`
     * 2. `HostCommand.CaptureAndSeal` on `sb-host` (`mlock` -> X25519 seal -> ciphertext only)
     * 3. `CompleteCapture` over E2E `Noise_IK` -> guest enclave unseals & writes to 1Password
     */
    fun executeArmedCaptureOffEdt(
        manifest: Manifest,
        environment: String,
        target: CaptureTarget,
    ): SecretMutationReceipt {
        assertOffEdt()
        val session = ensureRunningSession()
        val started = session.transport.executeEnclave(
            EnclaveRequest.BeginCapture(manifest, environment, target),
        ) as? EnclaveResult.CaptureStarted
            ?: throw EnclaveBridgeException("internal_error", "Unexpected BeginCapture response")

        val (sealedB64, mode) = session.transport.execute(
            HostCommand.CaptureAndSeal(
                pkCaptureB64 = started.pkCaptureB64,
                ttlMs = started.expiresInMs,
            ),
        ).requireSealedCapture()

        val stored = session.transport.executeEnclave(
            EnclaveRequest.CompleteCapture(
                captureId = started.captureId,
                sealedSecretB64 = sealedB64,
                mode = mode,
            ),
        ) as? EnclaveResult.SecretStored
            ?: throw EnclaveBridgeException("internal_error", "Unexpected CompleteCapture response")
        return stored.receipt
    }

    fun reconfigureCredentialsOffEdt() {
        assertOffEdt()
        val session = synchronized(lock) { managedProcess } ?: return
        pushBootstrapCredentials(session.transport)
    }

    fun restartSessionOffEdt() {
        assertOffEdt()
        val detached = synchronized(lock) { detachLocked() }
        teardownProcessOffEdt(detached)
        ensureRunningSession()
    }

    private fun ensureRunningSession(): ManagedHostProcess {
        synchronized(lock) {
            val existing = managedProcess
            if (existing != null && existing.process.isAlive) {
                return existing
            }
            val stale = detachLocked()
            teardownProcessOffEdt(stale)

            val settings = BridgeSettings.getInstance()
            val settingsState = settings.state
            val mode = HostBackendMode.fromWire(settingsState.backendMode)
            val pinnedPub32 = try {
                settingsState.resolvePinnedEnclavePubkey32()
            } catch (e: IllegalArgumentException) {
                throw EnclaveBridgeException(
                    "validation",
                    e.message ?: "Pinned enclave Noise static public key is required",
                )
            }

            val cidLease = if (mode == HostBackendMode.KVM_MICROVM) {
                try {
                    settings.acquireManagedGuestCidLease()
                } catch (e: Exception) {
                    pinnedPub32.fill(0)
                    throw EnclaveBridgeException(
                        "transport_failure",
                        e.message ?: "Unable to acquire host-wide AF_VSOCK guest CID lease",
                    )
                }
            } else {
                null
            }

            val (clientPriv32, clientPub32) = try {
                settings.loadOrCreateClientNoiseKeypairOffEdt()
            } catch (e: Exception) {
                pinnedPub32.fill(0)
                cidLease?.close()
                throw e
            }
            val clientPubHex = BridgeSettings.encodeHexString(clientPub32)

            val runtimeDir = try {
                createPrivateSocketDirectory()
            } catch (e: Exception) {
                pinnedPub32.fill(0)
                clientPriv32.fill(0)
                cidLease?.close()
                throw e
            }
            val ideSock = runtimeDir.resolve("h.sock")
            val localEncSock = runtimeDir.resolve("e.sock")

            val cliArgs = try {
                settingsState.buildHostCliArgs(
                    ideSocketPath = ideSock.toString(),
                    localEnclaveSocketPath = localEncSock.toString(),
                    authorizedClientPubkeyHex = clientPubHex,
                    effectiveGuestCid = cidLease?.cid ?: settingsState.guestCid,
                )
            } catch (e: IllegalArgumentException) {
                pinnedPub32.fill(0)
                clientPriv32.fill(0)
                cidLease?.close()
                cleanupRuntimeDir(runtimeDir)
                throw EnclaveBridgeException("validation", e.message ?: "Invalid SecretBridge host settings")
            }

            val pb = ProcessBuilder(cliArgs)
            val inheritedEnv = System.getenv()
            val cleanEnv = pb.environment()
            cleanEnv.clear()
            for (allowedKey in ALLOWED_HOST_ENV_KEYS) {
                val v = inheritedEnv[allowedKey]
                if (!v.isNullOrEmpty()) {
                    cleanEnv[allowedKey] = v
                }
            }

            val proc = try {
                pb.start()
            } catch (e: Exception) {
                pinnedPub32.fill(0)
                clientPriv32.fill(0)
                cidLease?.close()
                cleanupRuntimeDir(runtimeDir)
                throw EnclaveBridgeException(
                    "transport_failure",
                    "Failed launching sb-host binary '${cliArgs.firstOrNull()}': ${e.message}",
                )
            }

            val stderrRing = BoundedStderrRing()
            val stderrThread = Thread({
                try {
                    BufferedReader(InputStreamReader(proc.errorStream, StandardCharsets.UTF_8)).use { reader ->
                        while (true) {
                            val line = reader.readLine() ?: break
                            stderrRing.record(line)
                        }
                    }
                } catch (_: Exception) {
                }
            }, "sb-host-stderr-${project.locationHash.take(8)}").apply {
                isDaemon = true
                start()
            }

            val readyChars = readStartupBannerCharsWithTimeout(proc.inputStream, STARTUP_TIMEOUT_MS)
            if (readyChars == null) {
                pinnedPub32.fill(0)
                clientPriv32.fill(0)
                proc.destroyForcibly()
                cidLease?.close()
                cleanupRuntimeDir(runtimeDir)
                val detail = stderrRing.snapshot().ifBlank { "timed out waiting for SB_HOST_READY" }
                throw EnclaveBridgeException("transport_failure", "sb-host failed to start: $detail")
            }

            val parsedBanner = try {
                HostSocketTransport.parseReadyBannerChars(readyChars)
            } catch (e: Exception) {
                pinnedPub32.fill(0)
                clientPriv32.fill(0)
                proc.destroyForcibly()
                cidLease?.close()
                cleanupRuntimeDir(runtimeDir)
                throw e
            } finally {
                readyChars.fill('\u0000')
            }

            // Fail closed BEFORE opening any Noise_IK tunnel or transmitting bootstrap credentials:
            // never accept `SB_HOST_READY enckey=` from the untrusted host relay unless it matches `pinnedPub32`.
            if (
                parsedBanner.enclavePubkey32.size != 32 ||
                !NoiseIkSession.constantTimeEquals(pinnedPub32, parsedBanner.enclavePubkey32)
            ) {
                parsedBanner.authTokenChars.fill('\u0000')
                parsedBanner.enclavePubkey32.fill(0)
                pinnedPub32.fill(0)
                clientPriv32.fill(0)
                proc.destroyForcibly()
                cidLease?.close()
                cleanupRuntimeDir(runtimeDir)
                throw EnclaveBridgeException(
                    "unauthorized",
                    "Guest enclave Noise pubkey did not match configured pinned pubkey",
                )
            }

            val transport = HostSocketTransport(
                socketPath = parsedBanner.socketPath,
                authTokenHex = parsedBanner.authTokenChars,
                clientPrivateKey32 = clientPriv32,
                expectedEnclavePubkey32 = pinnedPub32,
            )
            parsedBanner.authTokenChars.fill('\u0000')
            parsedBanner.enclavePubkey32.fill(0)
            pinnedPub32.fill(0)
            clientPriv32.fill(0)

            val session = ManagedHostProcess(
                process = proc,
                transport = transport,
                runtimeDir = runtimeDir,
                stderrThread = stderrThread,
                cidLease = cidLease,
            )

            try {
                pushBootstrapCredentials(transport)
            } catch (e: Exception) {
                teardownProcessOffEdt(session)
                throw e
            }

            managedProcess = session
            return session
        }
    }

    private fun pushBootstrapCredentials(transport: HostSocketTransport) {
        val creds = BridgeSettings.getInstance().loadBootstrapCredentialsOffEdt()
        try {
            transport.executeEnclave(EnclaveRequest.ConfigureSession(creds))
        } finally {
            creds.wipe()
        }
    }

    private fun detachLocked(): ManagedHostProcess? {
        val current = managedProcess ?: return null
        managedProcess = null
        try {
            current.transport.close()
        } catch (_: Exception) {
        }
        return current
    }

    private fun teardownProcessOffEdt(session: ManagedHostProcess?) {
        if (session == null) return
        try {
            session.transport.close()
        } catch (_: Exception) {
        }
        try {
            session.process.destroy()
            if (!session.process.waitFor(2, TimeUnit.SECONDS)) {
                session.process.destroyForcibly()
            }
        } catch (_: Exception) {
        }
        try {
            session.cidLease?.close()
        } catch (_: Exception) {
        }
        cleanupRuntimeDir(session.runtimeDir)
    }

    override fun dispose() {
        val detached = synchronized(lock) { detachLocked() } ?: return
        val app = ApplicationManager.getApplication()
        if (app != null && SwingUtilities.isEventDispatchThread()) {
            app.executeOnPooledThread {
                teardownProcessOffEdt(detached)
            }
        } else {
            teardownProcessOffEdt(detached)
        }
    }

    private class ManagedHostProcess(
        val process: Process,
        val transport: HostSocketTransport,
        val runtimeDir: Path,
        val stderrThread: Thread,
        val cidLease: HostCidLease?,
    )

    private class BoundedStderrRing {
        private val lines = ArrayDeque<String>(16)

        @Synchronized
        fun record(line: String) {
            if (lines.size >= 16) lines.removeFirst()
            lines.addLast(line.take(240))
        }

        @Synchronized
        fun snapshot(): String = lines.joinToString(" | ")
    }

    companion object {
        private const val STARTUP_TIMEOUT_MS = 20_000L
        private const val MAX_BANNER_LINE_BYTES = 4096
        private val ALLOWED_HOST_ENV_KEYS = listOf(
            "PATH",
            "HOME",
            "USER",
            "LANG",
            "LC_ALL",
            "DISPLAY",
            "WAYLAND_DISPLAY",
            "XAUTHORITY",
            "XDG_RUNTIME_DIR",
        )

        fun getInstance(project: Project): EnclaveClient = project.service()

        fun assertOffEdt() {
            val app = ApplicationManager.getApplication()
            if (app != null) {
                app.assertIsNonDispatchThread()
            } else {
                check(!SwingUtilities.isEventDispatchThread()) {
                    "Enclave IPC must never execute on the Swing Event Dispatch Thread"
                }
            }
        }

        fun <T> runBackgroundTask(
            project: Project?,
            title: String,
            work: (ProgressIndicator) -> T,
            onSuccessEdt: (T) -> Unit,
            onErrorEdt: (Throwable) -> Unit,
        ) {
            ProgressManager.getInstance().run(object : Task.Backgroundable(project, title, true) {
                @Volatile
                private var computedResult: T? = null

                override fun run(indicator: ProgressIndicator) {
                    indicator.isIndeterminate = true
                    computedResult = work(indicator)
                }

                override fun onSuccess() {
                    @Suppress("UNCHECKED_CAST")
                    onSuccessEdt(computedResult as T)
                }

                override fun onThrowable(error: Throwable) {
                    if (error is ProcessCanceledException) return
                    onErrorEdt(error)
                }
            })
        }

        private fun createPrivateSocketDirectory(): Path {
            val home = System.getProperty("user.home")
                ?: throw EnclaveBridgeException("transport_failure", "Missing user.home property")
            val baseRoot = Paths.get(home, ".local", "run", "sb")
            Files.createDirectories(baseRoot)
            ensureOwnerOnlyPosixMode(baseRoot)
            val shortId = UUID.randomUUID().toString().replace("-", "").take(10)
            val dir = baseRoot.resolve(shortId)
            if (Files.exists(dir, LinkOption.NOFOLLOW_LINKS)) {
                throw EnclaveBridgeException("transport_failure", "Socket directory collision")
            }
            Files.createDirectory(dir)
            ensureOwnerOnlyPosixMode(dir)
            return dir
        }

        private fun ensureOwnerOnlyPosixMode(path: Path) {
            if (Files.isSymbolicLink(path)) {
                throw EnclaveBridgeException("validation", "Refusing symlinked socket runtime directory: $path")
            }
            try {
                Files.setPosixFilePermissions(path, PosixFilePermissions.fromString("rwx------"))
            } catch (_: UnsupportedOperationException) {
            }
        }

        private fun cleanupRuntimeDir(dir: Path) {
            try {
                Files.deleteIfExists(dir.resolve("h.sock"))
                Files.deleteIfExists(dir.resolve("e.sock"))
                Files.deleteIfExists(dir)
            } catch (_: Exception) {
            }
        }

        /**
         * Reads the `SB_HOST_READY` banner into a [CharArray] using a proper happens-before
         * [CountDownLatch] + [AtomicReference], then continues draining [stream] in the daemon
         * thread so `sb-host` never stalls on stdout (`H8`).
         */
        private fun readStartupBannerCharsWithTimeout(stream: InputStream, timeoutMs: Long): CharArray? {
            val resultRef = AtomicReference<CharArray?>(null)
            val latch = CountDownLatch(1)
            Thread({
                val lineBuf = ByteArray(MAX_BANNER_LINE_BYTES)
                var len = 0
                var emitted = false
                val drainBuf = ByteArray(1024)
                try {
                    while (!emitted) {
                        val b = stream.read()
                        if (b < 0) break
                        if (b == '\n'.code) {
                            val decoded = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(lineBuf, 0, len))
                            val chars = CharArray(decoded.remaining())
                            decoded.get(chars)
                            if (decoded.hasArray()) decoded.array().fill('\u0000')
                            resultRef.set(chars)
                            emitted = true
                            break
                        }
                        if (len < MAX_BANNER_LINE_BYTES) {
                            lineBuf[len++] = b.toByte()
                        }
                    }
                } catch (_: Exception) {
                } finally {
                    lineBuf.fill(0)
                    latch.countDown()
                }
                try {
                    while (stream.read(drainBuf) >= 0) {
                        // Drain subsequent stdout bytes to prevent pipe deadlock
                    }
                } catch (_: Exception) {
                } finally {
                    drainBuf.fill(0)
                }
            }, "sb-host-ready-reader").apply {
                isDaemon = true
                start()
            }
            if (!latch.await(timeoutMs, TimeUnit.MILLISECONDS)) {
                return null
            }
            return resultRef.getAndSet(null)
        }
    }
}
