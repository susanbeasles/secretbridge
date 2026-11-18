package me.vespoli.secretbridge

import com.intellij.openapi.Disposable
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.service
import com.intellij.openapi.diagnostic.Logger
import com.intellij.openapi.progress.ProgressIndicator
import com.intellij.openapi.progress.ProgressManager
import com.intellij.openapi.progress.Task
import com.intellij.openapi.project.Project
import java.io.BufferedReader
import java.io.ByteArrayOutputStream
import java.io.InputStreamReader
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.SocketChannel
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.LinkOption
import java.nio.file.Path
import java.nio.file.Paths
import java.nio.file.attribute.PosixFilePermissions
import java.util.ArrayDeque
import java.util.UUID
import java.util.concurrent.TimeUnit
import javax.swing.SwingUtilities

/**
 * Stateless per-call Unix domain socket client speaking newline-delimited
 * [AuthenticatedHostEnvelope] frames to `sb-host`.
 */
class HostSocketTransport(
    val socketPath: Path,
     authTokenHex: CharArray,
) : AutoCloseable {
    private val tokenChars: CharArray = authTokenHex.copyOf()

    @Synchronized
    fun execute(command: HostCommand): HostResponse {
        check(tokenChars.isNotEmpty()) { "HostSocketTransport has already been closed" }
        val envelope = AuthenticatedHostEnvelope(tokenChars, command)
        val requestBytes = JsonCodec.encodeUtf8(envelope.toJson(), appendNewline = true)
        try {
            val address = UnixDomainSocketAddress.of(socketPath)
            SocketChannel.open(StandardProtocolFamily.UNIX).use { channel ->
                channel.connect(address)
                val writeBuf = ByteBuffer.wrap(requestBytes)
                while (writeBuf.hasRemaining()) {
                    channel.write(writeBuf)
                }

                val responseLine = readSingleUtf8Line(channel, MAX_RESPONSE_BYTES)
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

    override fun close() {
        tokenChars.fill('\u0000')
    }

    companion object {
        private const val MAX_RESPONSE_BYTES = 1024 * 1024

        fun parseReadyBanner(line: String): Pair<Path, CharArray> {
            val trimmed = line.trim()
            if (!trimmed.startsWith("SB_HOST_READY ")) {
                throw EnclaveBridgeException(
                    "transport_failure",
                    "Unexpected sb-host startup banner",
                )
            }
            var socketRaw: String? = null
            var tokenChars: CharArray? = null
            val parts = trimmed.removePrefix("SB_HOST_READY ").split(' ')
            for (part in parts) {
                when {
                    part.startsWith("socket=") -> {
                        socketRaw = part.removePrefix("socket=").trim()
                    }
                    part.startsWith("token=") -> {
                        val start = "token=".length
                        tokenChars = CharArray(part.length - start) { idx -> part[start + idx] }
                    }
                }
            }
            val resolvedSocket = socketRaw?.takeIf { it.isNotEmpty() }
                ?: throw EnclaveBridgeException("transport_failure", "Missing socket path in SB_HOST_READY")
            val resolvedToken = tokenChars?.takeIf { it.size == 64 }
                ?: throw EnclaveBridgeException("transport_failure", "Invalid 64-hex token in SB_HOST_READY")
            return Paths.get(resolvedSocket) to resolvedToken
        }

        private fun readSingleUtf8Line(channel: SocketChannel, maxBytes: Int): String {
            val out = ByteArrayOutputStream(512)
            val single = ByteBuffer.allocate(4096)
            while (true) {
                single.clear()
                val n = channel.read(single)
                if (n < 0) break
                if (n == 0) continue
                single.flip()
                while (single.hasRemaining()) {
                    val b = single.get()
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
            }
            return String(out.toByteArray(), StandardCharsets.UTF_8)
        }
    }
}

@Service(Service.Level.PROJECT)
class EnclaveClient(private val project: Project) : Disposable {
    private val logger = Logger.getInstance(EnclaveClient::class.java)
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
        val response = executeHostCommandOffEdt(HostCommand.Enclave(request))
        return response.requireEnclaveResult()
    }

    fun reconfigureCredentialsOffEdt() {
        assertOffEdt()
        val session = synchronized(lock) { managedProcess } ?: return
        pushBootstrapCredentials(session.transport)
    }

    fun restartSessionOffEdt() {
        assertOffEdt()
        synchronized(lock) {
            stopLocked()
            ensureRunningSession()
        }
    }

    private fun ensureRunningSession(): ManagedHostProcess {
        synchronized(lock) {
            val existing = managedProcess
            if (existing != null && existing.process.isAlive) {
                return existing
            }
            stopLocked()

            val runtimeDir = createPrivateSocketDirectory()
            val ideSock = runtimeDir.resolve("h.sock")
            val localEncSock = runtimeDir.resolve("e.sock")
            val settingsState = BridgeSettings.getInstance().state
            val cliArgs = try {
                settingsState.buildHostCliArgs(ideSock.toString(), localEncSock.toString())
            } catch (e: IllegalArgumentException) {
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

            val readyLine = readStartupLineWithTimeout(proc, STARTUP_TIMEOUT_MS)
            if (readyLine == null) {
                proc.destroyForcibly()
                cleanupRuntimeDir(runtimeDir)
                val detail = stderrRing.snapshot().ifBlank { "timed out waiting for SB_HOST_READY" }
                throw EnclaveBridgeException("transport_failure", "sb-host failed to start: $detail")
            }

            val (boundSock, tokenChars) = try {
                HostSocketTransport.parseReadyBanner(readyLine)
            } catch (e: Exception) {
                proc.destroyForcibly()
                cleanupRuntimeDir(runtimeDir)
                throw e
            }

            val transport = HostSocketTransport(boundSock, tokenChars)
            tokenChars.fill('\u0000')

            val session = ManagedHostProcess(
                process = proc,
                transport = transport,
                runtimeDir = runtimeDir,
                stderrThread = stderrThread,
            )
            managedProcess = session

            try {
                pushBootstrapCredentials(transport)
            } catch (e: Exception) {
                logger.warn("Initial enclave session credential configuration failed: ${e.message}")
            }
            return session
        }
    }

    private fun pushBootstrapCredentials(transport: HostSocketTransport) {
        val creds = BridgeSettings.getInstance().loadBootstrapCredentialsOffEdt()
        try {
            if (!creds.isEmpty()) {
                transport.execute(HostCommand.Enclave(EnclaveRequest.ConfigureSession(creds)))
            }
        } finally {
            creds.wipe()
        }
    }

    private fun stopLocked() {
        val current = managedProcess ?: return
        managedProcess = null
        try {
            current.transport.close()
        } catch (_: Exception) {
        }
        try {
            current.process.destroy()
            if (!current.process.waitFor(2, TimeUnit.SECONDS)) {
                current.process.destroyForcibly()
            }
        } catch (_: Exception) {
        }
        cleanupRuntimeDir(current.runtimeDir)
    }

    override fun dispose() {
        synchronized(lock) {
            stopLocked()
        }
    }

    private class ManagedHostProcess(
        val process: Process,
        val transport: HostSocketTransport,
        val runtimeDir: Path,
        val stderrThread: Thread,
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
        private const val STARTUP_TIMEOUT_MS = 15_000L
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

        private fun readStartupLineWithTimeout(proc: Process, timeoutMs: Long): String? {
            var lineResult: String? = null
            val readerThread = Thread({
                try {
                    val reader = BufferedReader(InputStreamReader(proc.inputStream, StandardCharsets.UTF_8))
                    lineResult = reader.readLine()
                } catch (_: Exception) {
                }
            }, "sb-host-ready-reader").apply {
                isDaemon = true
                start()
            }
            readerThread.join(timeoutMs)
            return lineResult
        }
    }
}
