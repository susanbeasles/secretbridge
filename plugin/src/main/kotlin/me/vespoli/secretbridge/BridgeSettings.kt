package me.vespoli.secretbridge

import com.intellij.credentialStore.CredentialAttributes
import com.intellij.credentialStore.Credentials
import com.intellij.credentialStore.generateServiceName
import com.intellij.ide.passwordSafe.PasswordSafe
import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.components.PersistentStateComponent
import com.intellij.openapi.components.Service
import com.intellij.openapi.components.State
import com.intellij.openapi.components.Storage
import com.intellij.openapi.components.service
import com.intellij.util.xmlb.XmlSerializerUtil
import java.util.concurrent.atomic.AtomicInteger

enum class HostBackendMode(val wireValue: String, val displayLabel: String) {
    KVM_MICROVM("kvm_microvm", "Managed MicroVM (Linux KVM / macOS arm64 Virtualization.framework)"),
    EXISTING_VSOCK("existing_vsock", "Existing Vsock Enclave (Attach by Enclave Noise Pubkey)"),
    LOCAL_ENCLAVE_PROCESS("local_enclave_process", "Local Enclave Daemon Bridge (Development / Unix Socket)"),
    ;

    companion object {
        fun fromWire(value: String?): HostBackendMode =
            entries.firstOrNull { it.wireValue == value } ?: KVM_MICROVM
    }
}

@Service(Service.Level.APP)
@State(
    name = "SecretBridgeSettings",
    storages = [Storage("secretbridge.xml")],
)
class BridgeSettings : PersistentStateComponent<BridgeSettings.StateData> {
    data class StateData(
        var sbHostBinaryPath: String = "sb-host",
        var backendMode: String = HostBackendMode.KVM_MICROVM.wireValue,
        var vmmBinaryPath: String = defaultHostVmmPath(),
        var vmmSha256: String = "",
        var kernelPath: String = "",
        var kernelSha256: String = "",
        var initramfsPath: String = "",
        var initramfsSha256: String = "",
        var guestCid: Int = 42,
        var vsockPort: Int = 5190,
        var memoryMib: Int = 256,
        var enclavePubkeyHex: String = "",
        var enclaveBinaryPath: String = "/usr/local/bin/sb-enclave",
        var defaultGenerateLength: Int = 40,
        var defaultGenerateCharset: String = SecretCharset.ALPHANUMERIC_SYMBOLS.wireName,
        var pinnedLoadSecretsActionSha: String = "",
        var allowedGithubHost: String = "github.com",
        var allowedGithubOwnersCsv: String = "",
        var allowedAwsAccountsCsv: String = "",
        var pinnedEnclavePubkeyHex: String = "",
    ) {
        fun buildHostCliArgs(
            ideSocketPath: String,
            localEnclaveSocketPath: String,
            authorizedClientPubkeyHex: String,
            effectiveGuestCid: Int = guestCid,
        ): List<String> {
            val hostBin = sbHostBinaryPath.trim()
            require(hostBin.isNotEmpty() && !hostBin.startsWith("-")) {
                "sb-host binary path must be non-empty and must not start with '-'"
            }
            val args = ArrayList<String>()
            args.add(hostBin)
            args.add("--ide-socket")
            args.add(ideSocketPath)

            when (HostBackendMode.fromWire(backendMode)) {
                HostBackendMode.KVM_MICROVM -> {
                    require(isHex64(authorizedClientPubkeyHex)) {
                        "64-character client Noise static public key hex is required for Managed MicroVM mode"
                    }
                    require(kernelPath.isNotBlank() && initramfsPath.isNotBlank()) {
                        "Kernel and initramfs paths are required in Managed MicroVM mode"
                    }
                    require(isHex64(kernelSha256) && isHex64(initramfsSha256)) {
                        "64-character SHA-256 digests are required for both kernel and initramfs"
                    }
                    require(effectiveGuestCid in 3..65535) {
                        "Guest AF_VSOCK CID must be in 3..65535"
                    }
                    args.add("--backend")
                    args.add("auto")
                    val vmmTrimmed = vmmBinaryPath.trim()
                    if (vmmTrimmed.isNotEmpty()) {
                        require(!vmmTrimmed.startsWith("-")) {
                            "VMM binary path must not start with '-'"
                        }
                        args.add("--vmm-binary")
                        args.add(vmmTrimmed)
                    }
                    if (vmmSha256.isNotBlank()) {
                        require(isHex64(vmmSha256)) { "vmmSha256 must be 64-character hex when specified" }
                        args.add("--vmm-sha256")
                        args.add(vmmSha256.trim())
                    }
                    args.add("--kernel")
                    args.add(kernelPath.trim())
                    args.add("--kernel-sha256")
                    args.add(kernelSha256.trim())
                    args.add("--initramfs")
                    args.add(initramfsPath.trim())
                    args.add("--initramfs-sha256")
                    args.add(initramfsSha256.trim())
                    args.add("--authorized-client-pubkey-hex")
                    args.add(authorizedClientPubkeyHex.trim())
                    args.add("--guest-cid")
                    args.add(effectiveGuestCid.toString())
                    args.add("--vsock-port")
                    args.add(vsockPort.toString())
                    args.add("--memory-mib")
                    args.add(memoryMib.toString())
                }
                HostBackendMode.EXISTING_VSOCK -> {
                    require(isHex64(enclavePubkeyHex)) {
                        "64-character enclave Noise static public key hex is required for Existing Vsock mode"
                    }
                    args.add("--guest-cid")
                    args.add(effectiveGuestCid.toString())
                    args.add("--vsock-port")
                    args.add(vsockPort.toString())
                    args.add("--enclave-pubkey-hex")
                    args.add(enclavePubkeyHex.trim())
                }
                HostBackendMode.LOCAL_ENCLAVE_PROCESS -> {
                    require(isHex64(authorizedClientPubkeyHex)) {
                        "64-character client Noise static public key hex is required for Local Enclave mode"
                    }
                    val encBin = enclaveBinaryPath.trim()
                    require(encBin.isNotEmpty() && !encBin.startsWith("-")) {
                        "sb-enclave binary path must be non-empty and must not start with '-'"
                    }
                    args.add("--enclave-bin")
                    args.add(encBin)
                    args.add("--enclave-socket")
                    args.add(localEnclaveSocketPath)
                    args.add("--authorized-client-pubkey-hex")
                    args.add(authorizedClientPubkeyHex.trim())
                }
            }
            return args
        }

        fun parsedAllowedGithubHosts(): List<String> =
            allowedGithubHost.trim().takeIf { it.isNotEmpty() }?.let(::listOf) ?: emptyList()

        fun parsedAllowedGithubOwners(): List<String> =
            allowedGithubOwnersCsv.split(',').map { it.trim() }.filter { it.isNotEmpty() }

        fun parsedAllowedAwsAccounts(): List<String> =
            allowedAwsAccountsCsv.split(',').map { it.trim() }.filter { it.isNotEmpty() }
    }

    private var stateData = StateData()
    private val keyLock = Any()
    private var cachedFallbackNoisePrivateKey: ByteArray? = null

    override fun getState(): StateData = stateData

    override fun loadState(state: StateData) {
        XmlSerializerUtil.copyBean(state, stateData)
    }

    /**
     * Allocates a unique `AF_VSOCK` guest CID per open project so multiple IDE project windows
     * never collide on the same guest CID (`H8`).
     */
    fun allocateProjectGuestCid(): Int {
        val base = stateData.guestCid.coerceIn(3, 60_000)
        val offset = NEXT_CID_OFFSET.getAndIncrement() and 0x0FFF
        return base + offset
    }

    /**
     * Loads or generates the IDE's persistent 32-byte client `Noise_IK` static private key in
     * `PasswordSafe` strictly off the EDT (`C2`, `H8`). `sb-host` never sees this private key.
     */
    fun loadOrCreateClientNoiseKeypairOffEdt(): Pair<ByteArray, ByteArray> {
        ApplicationManager.getApplication()?.assertIsNonDispatchThread()
        synchronized(keyLock) {
            val app = ApplicationManager.getApplication()
            if (app == null || app.isHeadlessEnvironment) {
                val priv = cachedFallbackNoisePrivateKey?.copyOf() ?: run {
                    val (generatedPriv, _) = NoiseIkSession.generateStaticKeypair()
                    cachedFallbackNoisePrivateKey = generatedPriv.copyOf()
                    generatedPriv
                }
                val pub = NoiseIkSession.derivePublicKey(priv)
                return priv to pub
            }

            val existingChars = readKeychainSecretChars(KEY_CLIENT_NOISE_PRIVATE_KEY)
            if (existingChars != null) {
                val decoded = try {
                    decodeHexChars32OrNull(existingChars)
                } finally {
                    existingChars.fill('\u0000')
                }
                if (decoded != null) {
                    val pub = NoiseIkSession.derivePublicKey(decoded)
                    return decoded to pub
                }
            }

            val (freshPriv, freshPub) = NoiseIkSession.generateStaticKeypair()
            val hexChars = encodeHexChars(freshPriv)
            try {
                writeKeychainSecretChars(KEY_CLIENT_NOISE_PRIVATE_KEY, hexChars)
            } finally {
                hexChars.fill('\u0000')
            }
            return freshPriv to freshPub
        }
    }

    /**
     * Reads bootstrap tokens and configured destination allowlists strictly off the Swing EDT.
     * Returned [SessionCredentialsChars] holds mutable [CharArray] buffers that are wiped on transmit.
     */
    fun loadBootstrapCredentialsOffEdt(): SessionCredentialsChars {
        ApplicationManager.getApplication()?.assertIsNonDispatchThread()
        return SessionCredentialsChars(
            opServiceAccountToken = readKeychainSecretChars(KEY_OP_SERVICE_ACCOUNT_TOKEN),
            githubToken = readKeychainSecretChars(KEY_GITHUB_TOKEN),
            awsAccessKeyId = readKeychainSecretChars(KEY_AWS_ACCESS_KEY_ID),
            awsSecretAccessKey = readKeychainSecretChars(KEY_AWS_SECRET_ACCESS_KEY),
            awsSessionToken = readKeychainSecretChars(KEY_AWS_SESSION_TOKEN),
            allowedGithubHosts = stateData.parsedAllowedGithubHosts(),
            allowedGithubOwners = stateData.parsedAllowedGithubOwners(),
            allowedAwsAccountIds = stateData.parsedAllowedAwsAccounts(),
        )
    }

    /**
     * Persists or clears bootstrap tokens in OS keychain strictly off the Swing EDT,
     * wiping the caller-supplied [CharArray] buffers immediately afterwards.
     */
    fun saveBootstrapCredentialsOffEdt(
        opServiceAccountToken: CharArray?,
        githubToken: CharArray?,
        awsAccessKeyId: CharArray?,
        awsSecretAccessKey: CharArray?,
        awsSessionToken: CharArray?,
    ) {
        ApplicationManager.getApplication()?.assertIsNonDispatchThread()
        try {
            writeKeychainSecretChars(KEY_OP_SERVICE_ACCOUNT_TOKEN, opServiceAccountToken)
            writeKeychainSecretChars(KEY_GITHUB_TOKEN, githubToken)
            writeKeychainSecretChars(KEY_AWS_ACCESS_KEY_ID, awsAccessKeyId)
            writeKeychainSecretChars(KEY_AWS_SECRET_ACCESS_KEY, awsSecretAccessKey)
            writeKeychainSecretChars(KEY_AWS_SESSION_TOKEN, awsSessionToken)
        } finally {
            opServiceAccountToken?.fill('\u0000')
            githubToken?.fill('\u0000')
            awsAccessKeyId?.fill('\u0000')
            awsSecretAccessKey?.fill('\u0000')
            awsSessionToken?.fill('\u0000')
        }
    }

    fun hasStoredCredentialOffEdt(key: String): Boolean {
        ApplicationManager.getApplication()?.assertIsNonDispatchThread()
        val chars = readKeychainSecretChars(key) ?: return false
        val nonEmpty = chars.isNotEmpty()
        chars.fill('\u0000')
        return nonEmpty
    }

    private fun readKeychainSecretChars(key: String): CharArray? {
        val attrs = credentialAttributes(key)
        val creds = PasswordSafe.instance.get(attrs) ?: return null
        val rawChars = creds.password?.toCharArray() ?: return null
        if (rawChars.isEmpty()) return null
        return rawChars
    }

    private fun writeKeychainSecretChars(key: String, value: CharArray?) {
        val attrs = credentialAttributes(key)
        if (value == null || value.isEmpty()) {
            PasswordSafe.instance.set(attrs, null)
        } else {
            PasswordSafe.instance.set(attrs, Credentials("secretbridge", value))
        }
    }

    companion object {
        const val KEY_OP_SERVICE_ACCOUNT_TOKEN = "op_service_account_token"
        const val KEY_GITHUB_TOKEN = "github_token"
        const val KEY_AWS_ACCESS_KEY_ID = "aws_access_key_id"
        const val KEY_AWS_SECRET_ACCESS_KEY = "aws_secret_access_key"
        const val KEY_AWS_SESSION_TOKEN = "aws_session_token"
        const val KEY_CLIENT_NOISE_PRIVATE_KEY = "client_noise_private_key_hex"

        private val NEXT_CID_OFFSET = AtomicInteger(0)
        private val HEX_CHARS = charArrayOf(
            '0', '1', '2', '3', '4', '5', '6', '7',
            '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
        )

        fun defaultHostVmmPath(): String {
            val osName = System.getProperty("os.name")?.lowercase().orEmpty()
            if (osName.contains("mac")) return ""
            val arch = System.getProperty("os.arch")?.lowercase().orEmpty()
            return if (arch == "aarch64" || arch == "arm64") {
                "/usr/bin/qemu-system-aarch64"
            } else {
                "/usr/bin/qemu-system-x86_64"
            }
        }

        fun getInstance(): BridgeSettings = service()

        fun credentialAttributes(key: String): CredentialAttributes =
            CredentialAttributes(generateServiceName("me.vespoli.secretbridge", key))

        fun isHex64(value: String): Boolean {
            val trimmed = value.trim()
            if (trimmed.length != 64) return false
            return trimmed.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
        }

        fun encodeHexString(bytes: ByteArray): String = String(encodeHexChars(bytes))

        fun encodeHexChars(bytes: ByteArray): CharArray {
            val out = CharArray(bytes.size * 2)
            for (i in bytes.indices) {
                val v = bytes[i].toInt() and 0xFF
                out[i * 2] = HEX_CHARS[v ushr 4]
                out[i * 2 + 1] = HEX_CHARS[v and 0x0F]
            }
            return out
        }

        fun decodeHex32(hex: String): ByteArray {
            val chars = hex.trim().toCharArray()
            return try {
                decodeHexChars32OrNull(chars)
                    ?: throw IllegalArgumentException("Expected 64-character hex string")
            } finally {
                chars.fill('\u0000')
            }
        }

        fun decodeHexChars32OrNull(chars: CharArray): ByteArray? {
            if (chars.size != 64) return null
            val out = ByteArray(32)
            for (i in 0 until 32) {
                val hi = hexVal(chars[i * 2])
                val lo = hexVal(chars[i * 2 + 1])
                if (hi < 0 || lo < 0) {
                    out.fill(0)
                    return null
                }
                out[i] = ((hi shl 4) or lo).toByte()
            }
            return out
        }

        private fun hexVal(ch: Char): Int = when (ch) {
            in '0'..'9' -> ch.code - '0'.code
            in 'a'..'f' -> ch.code - 'a'.code + 10
            in 'A'..'F' -> ch.code - 'A'.code + 10
            else -> -1
        }
    }
}
