package me.vespoli.secretbridge

import com.intellij.openapi.application.ApplicationManager
import com.intellij.openapi.options.Configurable
import com.intellij.openapi.project.ProjectManager
import com.intellij.openapi.ui.ComboBox
import com.intellij.ui.components.JBCheckBox
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBPasswordField
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBTextArea
import com.intellij.ui.components.JBTextField
import com.intellij.util.ui.FormBuilder
import com.intellij.util.ui.JBUI
import java.awt.BorderLayout
import javax.swing.DefaultListCellRenderer
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.JSpinner
import javax.swing.SpinnerNumberModel
import javax.swing.SwingUtilities

class BridgeSettingsConfigurable : Configurable {
    private val sbHostBinaryField = JBTextField()
    private val backendModeCombo = ComboBox(HostBackendMode.entries.toTypedArray())
    private val vmmBinaryField = JBTextField()
    private val vmmSha256Field = JBTextField()
    private val kernelPathField = JBTextField()
    private val kernelSha256Field = JBTextField()
    private val initramfsPathField = JBTextField()
    private val initramfsSha256Field = JBTextField()
    private val guestCidSpinner = JSpinner(SpinnerNumberModel(42, 3, 60000, 1))
    private val vsockPortSpinner = JSpinner(SpinnerNumberModel(5190, 1024, 65535, 1))
    private val memoryMibSpinner = JSpinner(SpinnerNumberModel(256, 128, 4096, 64))
    private val enclavePubkeyHexField = JBTextField()
    private val pinnedEnclavePubkeyHexField = JBTextField()
    private val enclaveBinaryField = JBTextField()
    private val enclaveKeyFileField = JBTextField()

    private val allowedGithubHostField = JBTextField()
    private val allowedGithubOwnersField = JBTextField()
    private val allowedAwsAccountsField = JBTextField()

    private val defaultGenLengthSpinner = JSpinner(SpinnerNumberModel(40, 16, 256, 4))
    private val defaultGenCharsetCombo = ComboBox(SecretCharset.entries.toTypedArray())
    private val pinnedActionShaField = JBTextField()

    private val opTokenField = JBPasswordField()
    private val githubTokenField = JBPasswordField()
    private val awsAccessKeyField = JBPasswordField()
    private val awsSecretKeyField = JBPasswordField()
    private val awsSessionTokenField = JBPasswordField()
    private val clearStoredCredentialsCheck = JBCheckBox("Clear stored OS Keychain credentials on Apply")
    private val credentialStatusLabel = JBLabel("Checking OS Keychain status...")

    private val diagnosticsOutput = JBTextArea(6, 60).apply {
        isEditable = false
        lineWrap = true
        wrapStyleWord = true
    }

    private var rootPanel: JPanel? = null
    private var listenerRegistered = false

    override fun getDisplayName(): String = "SecretBridge for 1Password"

    override fun createComponent(): JComponent {
        backendModeCombo.renderer = DefaultListCellRenderer()
        if (!listenerRegistered) {
            backendModeCombo.addActionListener { updateModeFieldVisibility() }
            listenerRegistered = true
        }
        vmmSha256Field.emptyText.text = "Optional 64-hex SHA-256 of QEMU binary (Linux KVM)"
        pinnedEnclavePubkeyHexField.emptyText.text =
            "Required 64-hex guest enclave Noise pubkey (vm/out/enclave-pubkey.txt)"
        enclaveKeyFileField.emptyText.text =
            "Mode-0400 enclave Noise key file (provisioned via sb-enclave --generate-identity)"
        allowedGithubHostField.emptyText.text = "github.com (single authorized host)"
        allowedGithubOwnersField.emptyText.text = "Optional comma-separated GitHub orgs/owners"
        allowedAwsAccountsField.emptyText.text = "Optional comma-separated 12-digit AWS account IDs"
        opTokenField.emptyText.text = "Leave blank to keep existing OS Keychain token"
        githubTokenField.emptyText.text = "Leave blank to keep existing GitHub token"
        awsAccessKeyField.emptyText.text = "Optional (leave blank to keep existing)"
        awsSecretKeyField.emptyText.text = "Optional (leave blank to keep existing)"
        awsSessionTokenField.emptyText.text = "Optional session token"
        pinnedActionShaField.emptyText.text = "40-char lowercase commit SHA for 1Password/load-secrets-action"

        val testButton = JButton("Test Enclave & Service Account Capabilities").apply {
            addActionListener { runDiagnosticsOffEdt() }
        }

        val form = FormBuilder.createFormBuilder()
            .addLabeledComponent("sb-host binary path:", sbHostBinaryField, 1, false)
            .addLabeledComponent("Enclave backend mode:", backendModeCombo, 1, false)
            .addSeparator()
            .addLabeledComponent("VMM binary (Linux KVM):", vmmBinaryField, 1, false)
            .addLabeledComponent("VMM binary SHA-256 (optional):", vmmSha256Field, 1, false)
            .addLabeledComponent("Guest kernel image:", kernelPathField, 1, false)
            .addLabeledComponent("Guest kernel SHA-256:", kernelSha256Field, 1, false)
            .addLabeledComponent("Guest initramfs image:", initramfsPathField, 1, false)
            .addLabeledComponent("Guest initramfs SHA-256:", initramfsSha256Field, 1, false)
            .addLabeledComponent("Base AF_VSOCK CID:", guestCidSpinner, 1, false)
            .addLabeledComponent("Guest AF_VSOCK port:", vsockPortSpinner, 1, false)
            .addLabeledComponent("MicroVM RAM (MiB):", memoryMibSpinner, 1, false)
            .addLabeledComponent("Existing enclave pubkey (64-hex):", enclavePubkeyHexField, 1, false)
            .addLabeledComponent("Pinned enclave pubkey (64-hex, required):", pinnedEnclavePubkeyHexField, 1, false)
            .addLabeledComponent("Local sb-enclave binary:", enclaveBinaryField, 1, false)
            .addLabeledComponent("Local enclave key file:", enclaveKeyFileField, 1, false)
            .addSeparator()
            .addLabeledComponent("Authorized GitHub host:", allowedGithubHostField, 1, false)
            .addLabeledComponent("Allowed GitHub owners (CSV):", allowedGithubOwnersField, 1, false)
            .addLabeledComponent("Allowed AWS accounts (CSV):", allowedAwsAccountsField, 1, false)
            .addLabeledComponent("Default generated length:", defaultGenLengthSpinner, 1, false)
            .addLabeledComponent("Default generated charset:", defaultGenCharsetCombo, 1, false)
            .addLabeledComponent("Pinned 1Password Action SHA:", pinnedActionShaField, 1, false)
            .addSeparator()
            .addComponent(credentialStatusLabel)
            .addLabeledComponent("1Password Service Account Token:", opTokenField, 1, false)
            .addLabeledComponent("GitHub Actions Token:", githubTokenField, 1, false)
            .addLabeledComponent("AWS Access Key ID:", awsAccessKeyField, 1, false)
            .addLabeledComponent("AWS Secret Access Key:", awsSecretKeyField, 1, false)
            .addLabeledComponent("AWS Session Token:", awsSessionTokenField, 1, false)
            .addComponent(clearStoredCredentialsCheck)
            .addSeparator()
            .addComponent(testButton)
            .addComponentFillVertically(JBScrollPane(diagnosticsOutput), 8)
            .panel

        val container = JPanel(BorderLayout()).apply {
            border = JBUI.Borders.empty(8)
            add(JBScrollPane(form), BorderLayout.CENTER)
        }
        rootPanel = container
        reset()
        return container
    }

    private fun updateModeFieldVisibility() {
        val mode = backendModeCombo.selectedItem as? HostBackendMode ?: HostBackendMode.KVM_MICROVM
        val isManagedVm = mode == HostBackendMode.KVM_MICROVM
        val isExistingVsock = mode == HostBackendMode.EXISTING_VSOCK
        val isLocalProc = mode == HostBackendMode.LOCAL_ENCLAVE_PROCESS

        vmmBinaryField.isEnabled = isManagedVm
        vmmSha256Field.isEnabled = isManagedVm
        kernelPathField.isEnabled = isManagedVm
        kernelSha256Field.isEnabled = isManagedVm
        initramfsPathField.isEnabled = isManagedVm
        initramfsSha256Field.isEnabled = isManagedVm
        memoryMibSpinner.isEnabled = isManagedVm

        guestCidSpinner.isEnabled = isManagedVm || isExistingVsock
        vsockPortSpinner.isEnabled = isManagedVm || isExistingVsock
        enclavePubkeyHexField.isEnabled = isExistingVsock
        pinnedEnclavePubkeyHexField.isEnabled = isManagedVm || isLocalProc
        enclaveBinaryField.isEnabled = isLocalProc
        enclaveKeyFileField.isEnabled = isLocalProc
    }

    override fun isModified(): Boolean {
        val s = BridgeSettings.getInstance().state
        val selectedMode = (backendModeCombo.selectedItem as? HostBackendMode ?: HostBackendMode.KVM_MICROVM).wireValue
        val selectedCharset =
            (defaultGenCharsetCombo.selectedItem as? SecretCharset ?: SecretCharset.ALPHANUMERIC_SYMBOLS).wireName

        if (sbHostBinaryField.text.trim() != s.sbHostBinaryPath) return true
        if (selectedMode != s.backendMode) return true
        if (vmmBinaryField.text.trim() != s.vmmBinaryPath) return true
        if (vmmSha256Field.text.trim() != s.vmmSha256) return true
        if (kernelPathField.text.trim() != s.kernelPath) return true
        if (kernelSha256Field.text.trim() != s.kernelSha256) return true
        if (initramfsPathField.text.trim() != s.initramfsPath) return true
        if (initramfsSha256Field.text.trim() != s.initramfsSha256) return true
        if ((guestCidSpinner.value as Int) != s.guestCid) return true
        if ((vsockPortSpinner.value as Int) != s.vsockPort) return true
        if ((memoryMibSpinner.value as Int) != s.memoryMib) return true
        if (enclavePubkeyHexField.text.trim() != s.enclavePubkeyHex) return true
        if (pinnedEnclavePubkeyHexField.text.trim() != s.pinnedEnclavePubkeyHex) return true
        if (enclaveBinaryField.text.trim() != s.enclaveBinaryPath) return true
        if (enclaveKeyFileField.text.trim() != s.enclaveKeyFilePath) return true
        if (allowedGithubHostField.text.trim() != s.allowedGithubHost) return true
        if (allowedGithubOwnersField.text.trim() != s.allowedGithubOwnersCsv) return true
        if (allowedAwsAccountsField.text.trim() != s.allowedAwsAccountsCsv) return true
        if ((defaultGenLengthSpinner.value as Int) != s.defaultGenerateLength) return true
        if (selectedCharset != s.defaultGenerateCharset) return true
        if (pinnedActionShaField.text.trim() != s.pinnedLoadSecretsActionSha) return true
        if (clearStoredCredentialsCheck.isSelected) return true
        if (hasPendingPasswordInput(opTokenField)) return true
        if (hasPendingPasswordInput(githubTokenField)) return true
        if (hasPendingPasswordInput(awsAccessKeyField)) return true
        if (hasPendingPasswordInput(awsSecretKeyField)) return true
        if (hasPendingPasswordInput(awsSessionTokenField)) return true
        return false
    }

    private fun hasPendingPasswordInput(field: JBPasswordField): Boolean {
        val chars = field.password
        val nonEmpty = chars.isNotEmpty()
        chars.fill('\u0000')
        return nonEmpty
    }

    private fun wipeAllPasswordFields() {
        wipePasswordField(opTokenField)
        wipePasswordField(githubTokenField)
        wipePasswordField(awsAccessKeyField)
        wipePasswordField(awsSecretKeyField)
        wipePasswordField(awsSessionTokenField)
    }

    private fun wipePasswordField(field: JBPasswordField) {
        try {
            val doc = field.document
            val len = doc.length
            if (len > 0) {
                doc.remove(0, len)
                doc.insertString(0, "0".repeat(len), null)
                doc.remove(0, doc.length)
            }
        } catch (_: Exception) {
        }
        field.text = ""
    }

    override fun apply() {
        val settings = BridgeSettings.getInstance()
        val s = settings.state
        s.sbHostBinaryPath = sbHostBinaryField.text.trim().ifEmpty { "sb-host" }
        s.backendMode = (backendModeCombo.selectedItem as? HostBackendMode ?: HostBackendMode.KVM_MICROVM).wireValue
        s.vmmBinaryPath = vmmBinaryField.text.trim()
        s.vmmSha256 = vmmSha256Field.text.trim()
        s.kernelPath = kernelPathField.text.trim()
        s.kernelSha256 = kernelSha256Field.text.trim()
        s.initramfsPath = initramfsPathField.text.trim()
        s.initramfsSha256 = initramfsSha256Field.text.trim()
        s.guestCid = guestCidSpinner.value as Int
        s.vsockPort = vsockPortSpinner.value as Int
        s.memoryMib = memoryMibSpinner.value as Int
        s.enclavePubkeyHex = enclavePubkeyHexField.text.trim()
        s.pinnedEnclavePubkeyHex = pinnedEnclavePubkeyHexField.text.trim()
        s.enclaveBinaryPath = enclaveBinaryField.text.trim().ifEmpty { "/usr/local/bin/sb-enclave" }
        s.enclaveKeyFilePath = enclaveKeyFileField.text.trim()
        s.allowedGithubHost = allowedGithubHostField.text.trim().ifEmpty { "github.com" }
        s.allowedGithubOwnersCsv = allowedGithubOwnersField.text.trim()
        s.allowedAwsAccountsCsv = allowedAwsAccountsField.text.trim()
        s.defaultGenerateLength = defaultGenLengthSpinner.value as Int
        s.defaultGenerateCharset =
            (defaultGenCharsetCombo.selectedItem as? SecretCharset ?: SecretCharset.ALPHANUMERIC_SYMBOLS).wireName
        s.pinnedLoadSecretsActionSha = pinnedActionShaField.text.trim()

        val clearAll = clearStoredCredentialsCheck.isSelected
        val opChars = opTokenField.password
        val ghChars = githubTokenField.password
        val awsIdChars = awsAccessKeyField.password
        val awsSecChars = awsSecretKeyField.password
        val awsSessChars = awsSessionTokenField.password

        wipeAllPasswordFields()
        clearStoredCredentialsCheck.isSelected = false

        settings.submitCredentialTransaction {
            try {
                if (clearAll) {
                    settings.saveBootstrapCredentialsOffEdt(null, null, null, null, null)
                } else {
                    val existing = settings.loadBootstrapCredentialsOffEdt()
                    try {
                        settings.saveBootstrapCredentialsOffEdt(
                            opServiceAccountToken = if (opChars.isNotEmpty()) opChars else existing.opServiceAccountToken?.copyOf(),
                            githubToken = if (ghChars.isNotEmpty()) ghChars else existing.githubToken?.copyOf(),
                            awsAccessKeyId = if (awsIdChars.isNotEmpty()) awsIdChars else existing.awsAccessKeyId?.copyOf(),
                            awsSecretAccessKey = if (awsSecChars.isNotEmpty()) awsSecChars else existing.awsSecretAccessKey?.copyOf(),
                            awsSessionToken = if (awsSessChars.isNotEmpty()) awsSessChars else existing.awsSessionToken?.copyOf(),
                        )
                    } finally {
                        existing.wipe()
                    }
                }
                for (openProject in ProjectManager.getInstance().openProjects) {
                    if (!openProject.isDisposed) {
                        try {
                            EnclaveClient.getInstance(openProject).restartSessionOffEdt()
                        } catch (_: Exception) {
                        }
                    }
                }
                refreshKeychainStatusOffEdt()
            } finally {
                opChars.fill('\u0000')
                ghChars.fill('\u0000')
                awsIdChars.fill('\u0000')
                awsSecChars.fill('\u0000')
                awsSessChars.fill('\u0000')
            }
        }
    }

    override fun reset() {
        val settings = BridgeSettings.getInstance()
        val s = settings.state
        sbHostBinaryField.text = s.sbHostBinaryPath
        backendModeCombo.selectedItem = HostBackendMode.fromWire(s.backendMode)
        vmmBinaryField.text = s.vmmBinaryPath
        vmmSha256Field.text = s.vmmSha256
        kernelPathField.text = s.kernelPath
        kernelSha256Field.text = s.kernelSha256
        initramfsPathField.text = s.initramfsPath
        initramfsSha256Field.text = s.initramfsSha256
        guestCidSpinner.value = s.guestCid
        vsockPortSpinner.value = s.vsockPort
        memoryMibSpinner.value = s.memoryMib
        enclavePubkeyHexField.text = s.enclavePubkeyHex
        pinnedEnclavePubkeyHexField.text = s.pinnedEnclavePubkeyHex
        enclaveBinaryField.text = s.enclaveBinaryPath
        enclaveKeyFileField.text = s.enclaveKeyFilePath
        allowedGithubHostField.text = s.allowedGithubHost
        allowedGithubOwnersField.text = s.allowedGithubOwnersCsv
        allowedAwsAccountsField.text = s.allowedAwsAccountsCsv
        defaultGenLengthSpinner.value = s.defaultGenerateLength
        defaultGenCharsetCombo.selectedItem = SecretCharset.fromWire(s.defaultGenerateCharset)
        pinnedActionShaField.text = s.pinnedLoadSecretsActionSha

        wipeAllPasswordFields()
        clearStoredCredentialsCheck.isSelected = false
        updateModeFieldVisibility()

        settings.submitCredentialTransaction {
            refreshKeychainStatusOffEdt()
        }
    }

    private fun refreshKeychainStatusOffEdt() {
        val app = ApplicationManager.getApplication()
        if (app != null && app.isHeadlessEnvironment) {
            SwingUtilities.invokeLater {
                credentialStatusLabel.text = "OS Keychain status unavailable in headless mode."
            }
            return
        }
        val settings = BridgeSettings.getInstance()
        val hasOp = settings.hasStoredCredentialOffEdt(BridgeSettings.KEY_OP_SERVICE_ACCOUNT_TOKEN)
        val hasGh = settings.hasStoredCredentialOffEdt(BridgeSettings.KEY_GITHUB_TOKEN)
        val hasAws = settings.hasStoredCredentialOffEdt(BridgeSettings.KEY_AWS_SECRET_ACCESS_KEY)
        val pubKey = settings.loadOrCreateClientNoisePublicKeyOffEdt()
        val pubShort = BridgeSettings.encodeHexString(pubKey).take(16)
        val summary = buildString {
            append("OS Keychain tokens: ")
            append("1Password=").append(if (hasOp) "present" else "unset").append(", ")
            append("GitHub=").append(if (hasGh) "present" else "unset").append(", ")
            append("AWS=").append(if (hasAws) "present" else "unset")
            append(" | IDE Noise pubkey: ").append(pubShort).append("...")
        }
        SwingUtilities.invokeLater {
            credentialStatusLabel.text = summary
        }
    }

    private fun runDiagnosticsOffEdt() {
        val project = ProjectManager.getInstance().openProjects.firstOrNull { !it.isDisposed }
        if (project == null) {
            diagnosticsOutput.text = "Open a project first to launch the project-scoped enclave bridge."
            return
        }
        diagnosticsOutput.text = "Connecting over E2E Noise_IK and querying enclave capabilities..."
        EnclaveClient.runBackgroundTask(
            project = project,
            title = "Testing SecretBridge Enclave",
            work = {
                val client = EnclaveClient.getInstance(project)
                val doctor = client.executeEnclaveOffEdt(EnclaveRequest.Doctor()) as? EnclaveResult.Doctor
                val caps = client.executeEnclaveOffEdt(EnclaveRequest.Capabilities) as? EnclaveResult.Capabilities
                buildString {
                    if (caps != null) {
                        val c = caps.capabilities
                        appendLine("Authenticated: ${c.authenticated}")
                        appendLine("Can Create Vaults: ${c.canCreateVaults}")
                        appendLine("Accessible Vaults: ${c.accessibleVaultIds.size}")
                        appendLine("Policy Notice: ${c.notice}")
                    }
                    if (doctor != null) {
                        appendLine("--- Doctor Checks ---")
                        for (entry in doctor.entries) {
                            val suffix = entry.detail?.let { " ($it)" } ?: ""
                            appendLine("[${entry.status.uppercase()}] ${entry.subsystem}$suffix")
                        }
                    }
                }
            },
            onSuccessEdt = { text ->
                diagnosticsOutput.text = text
            },
            onErrorEdt = { err ->
                diagnosticsOutput.text = "Enclave check failed: ${err.message}"
            },
        )
    }

    override fun disposeUIResources() {
        wipeAllPasswordFields()
        rootPanel = null
    }
}
