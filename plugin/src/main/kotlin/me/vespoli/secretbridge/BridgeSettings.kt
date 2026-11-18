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

enum class HostBackendMode(val wireValue: String, val displayLabel: String) {
    KVM_MICROVM("kvm_microvm", "Managed KVM MicroVM (Linux AF_VSOCK)"),
    EXISTING_VSOCK("existing_vsock", "Existing VZ / MicroVM Enclave (macOS arm64 / Linux AF_VSOCK)"),
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
        var vmmBinaryPath: String = "qemu-system-x86_64",
        var kernelPath: String = "",
        var kernelSha256: String = "",
        var initramfsPath: String = "",
        var initramfsSha256: String = "",
        var guestCid: Int = 42,
        var vsockPort: Int = 5190,
        var memoryMib: Int = 256,
        var enclavePubkeyHex: String = "",
        var enclaveBinaryPath: String = "sb-enclave",
        var defaultGenerateLength: Int = 40,
        var defaultGenerateCharset: String = SecretCharset.ALPHANUMERIC_SYMBOLS.wireName,
        var pinnedLoadSecretsActionSha: String = "",
    ) {
        fun buildHostCliArgs(ideSocketPath: String, localEnclaveSocketPath: String): List<String> {
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
                    require(kernelPath.isNotBlank() && initramfsPath.isNotBlank()) {
                        "Kernel and initramfs paths are required in Managed KVM MicroVM mode"
                    }
                    require(isHex64(kernelSha256) && isHex64(initramfsSha256)) {
                        "64-character SHA-256 digests are required for both kernel and initramfs"
                    }
                    if (vmmBinaryPath.isNotBlank()) {
                        args.add("--vmm-binary")
                        args.add(vmmBinaryPath.trim())
                    }
                    args.add("--kernel")
                    args.add(kernelPath.trim())
                    args.add("--kernel-sha256")
                    args.add(kernelSha256.trim())
                    args.add("--initramfs")
                    args.add(initramfsPath.trim())
                    args.add("--initramfs-sha256")
                    args.add(initramfsSha256.trim())
                    args.add("--guest-cid")
                    args.add(guestCid.toString())
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
                    args.add(guestCid.toString())
                    args.add("--vsock-port")
                    args.add(vsockPort.toString())
                    args.add("--enclave-pubkey-hex")
                    args.add(enclavePubkeyHex.trim())
                }
                HostBackendMode.LOCAL_ENCLAVE_PROCESS -> {
                    val encBin = enclaveBinaryPath.trim()
                    require(encBin.isNotEmpty() && !encBin.startsWith("-")) {
                        "sb-enclave binary path must be non-empty"
                    }
                    args.add("--enclave-bin")
                    args.add(encBin)
                    args.add("--enclave-socket")
                    args.add(localEnclaveSocketPath)
                }
            }
            return args
        }
    }

    private var stateData = StateData()

    override fun getState(): StateData = stateData

    override fun loadState(state: StateData) {
        XmlSerializerUtil.copyBean(state, stateData)
    }

    /**
     * Reads bootstrap tokens from the OS credential store strictly off the Swing EDT.
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
        val seq: CharSequence = creds.password ?: return null
        if (seq.isEmpty()) return null
        return CharArray(seq.length) { idx -> seq[idx] }
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

        fun getInstance(): BridgeSettings = service()

        fun credentialAttributes(key: String): CredentialAttributes =
            CredentialAttributes(generateServiceName("me.vespoli.secretbridge", key))

        fun isHex64(value: String): Boolean {
            val trimmed = value.trim()
            if (trimmed.length != 64) return false
            return trimmed.all { it in '0'..'9' || it in 'a'..'f' || it in 'A'..'F' }
        }
    }
}
