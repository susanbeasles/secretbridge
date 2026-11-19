package me.vespoli.secretbridge

import com.intellij.openapi.Disposable
import com.intellij.openapi.ide.CopyPasteManager
import com.intellij.openapi.project.DumbAware
import com.intellij.openapi.project.Project
import com.intellij.openapi.ui.ComboBox
import com.intellij.openapi.ui.DialogWrapper
import com.intellij.openapi.ui.Messages
import com.intellij.openapi.util.Disposer
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.openapi.wm.ToolWindow
import com.intellij.openapi.wm.ToolWindowFactory
import com.intellij.ui.JBSplitter
import com.intellij.ui.components.JBCheckBox
import com.intellij.ui.components.JBLabel
import com.intellij.ui.components.JBList
import com.intellij.ui.components.JBScrollPane
import com.intellij.ui.components.JBTextArea
import com.intellij.ui.components.JBTextField
import com.intellij.ui.content.ContentFactory
import com.intellij.ui.table.JBTable
import com.intellij.util.ui.FormBuilder
import com.intellij.util.ui.JBUI
import java.awt.BorderLayout
import java.awt.FlowLayout
import java.awt.GridLayout
import java.awt.datatransfer.StringSelection
import javax.swing.DefaultListModel
import javax.swing.JButton
import javax.swing.JComponent
import javax.swing.JPanel
import javax.swing.JSpinner
import javax.swing.ListSelectionModel
import javax.swing.SpinnerNumberModel
import javax.swing.Timer
import javax.swing.table.AbstractTableModel

data class VaultCreateButtonState(
    val enabled: Boolean,
    val tooltip: String,
)

object VaultUiPolicy {
    fun computeCreateVaultButtonState(caps: ServiceAccountCapabilities?): VaultCreateButtonState {
        if (caps == null || !caps.authenticated) {
            return VaultCreateButtonState(
                enabled = false,
                tooltip = "Connect an authenticated 1Password Service Account token in Settings first.",
            )
        }
        if (!caps.canCreateVaults) {
            return VaultCreateButtonState(
                enabled = false,
                tooltip = "Disabled: OP_SERVICE_ACCOUNT_TOKEN lacks 'can_create_vaults'. " +
                    "Service Accounts can only modify/delete vaults they created and cannot access Personal/Private vaults.",
            )
        }
        return VaultCreateButtonState(
            enabled = true,
            tooltip = "Create a new 1Password vault owned by this Service Account.",
        )
    }
}

class SecretsToolWindowFactory : ToolWindowFactory, DumbAware {
    override fun createToolWindowContent(project: Project, toolWindow: ToolWindow) {
        val panel = SecretsToolWindowPanel(project)
        val content = ContentFactory.getInstance().createContent(panel, "", false)
        Disposer.register(content, panel)
        toolWindow.contentManager.addContent(content)
    }
}

class SecretsToolWindowPanel(private val project: Project) : JPanel(BorderLayout()), Disposable {
    private val envCombo = ComboBox<String>()
    private val statusBanner = JBLabel("Click Refresh to load secretbridge.json and query enclave.")
    private val captureCountdownLabel = JBLabel("")

    private val vaultListModel = DefaultListModel<String>()
    private val vaultList = JBList(vaultListModel)
    private val createVaultButton = JButton("Create Vault...")

    private val itemListModel = DefaultListModel<ItemSummary>()
    private val itemList = JBList(itemListModel)

    private val fieldTableModel = FieldTableModel()
    private val fieldTable = JBTable(fieldTableModel)

    private val bindingsTableModel = BindingsTableModel()
    private val bindingsTable = JBTable(bindingsTableModel)

    private var currentManifest: Manifest? = null
    private var currentCapabilities: ServiceAccountCapabilities? = null
    private var countdownTimer: Timer? = null

    init {
        border = JBUI.Borders.empty(6)
        updateVaultButtonState(null)

        val topBar = JPanel(BorderLayout(8, 4)).apply {
            val controls = JPanel(FlowLayout(FlowLayout.LEFT, 6, 0))
            val refreshBtn = JButton("Refresh").apply { addActionListener { reloadManifestAndVaultState() } }
            val initBtn = JButton("Init Manifest...").apply { addActionListener { promptInitManifest() } }
            createVaultButton.addActionListener { promptCreateVault() }

            envCombo.addActionListener {
                onEnvironmentSelectionChanged()
            }

            controls.add(JBLabel("Env:"))
            controls.add(envCombo)
            controls.add(refreshBtn)
            controls.add(initBtn)
            controls.add(createVaultButton)

            val statusPanel = JPanel(GridLayout(2, 1, 0, 2)).apply {
                add(statusBanner)
                add(captureCountdownLabel)
            }
            add(controls, BorderLayout.NORTH)
            add(statusPanel, BorderLayout.SOUTH)
        }

        itemList.selectionMode = ListSelectionModel.SINGLE_SELECTION
        itemList.setCellRenderer { _, value, _, isSelected, _ ->
            JBLabel("${value.title} [${value.category}]").apply {
                isOpaque = true
                if (isSelected) {
                    background = itemList.selectionBackground
                    foreground = itemList.selectionForeground
                } else {
                    background = itemList.background
                    foreground = itemList.foreground
                }
                border = JBUI.Borders.empty(2, 4)
            }
        }
        itemList.addListSelectionListener { event ->
            if (!event.valueIsAdjusting) {
                val selected = itemList.selectedValue
                if (selected != null) {
                    loadFieldsForItem(selected)
                } else {
                    fieldTableModel.setRows(emptyList())
                }
            }
        }

        val itemActionRow = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2)).apply {
            add(JButton("Generate Secret (In-VM)...").apply { addActionListener { promptGenerateSecret() } })
            add(JButton("Capture Secret (15s Armed Copy)...").apply { addActionListener { promptArmedCapture() } })
            add(JButton("Bind Selected Field...").apply { addActionListener { promptBindSelectedField() } })
            add(JButton("Archive Item").apply { addActionListener { confirmArchiveSelectedItem() } })
        }

        val itemsFieldsSplitter = JBSplitter(false, 0.42f).apply {
            firstComponent = JPanel(BorderLayout()).apply {
                add(JBLabel("Vault Items (Safe Categories Metadata)"), BorderLayout.NORTH)
                add(JBScrollPane(itemList), BorderLayout.CENTER)
            }
            secondComponent = JPanel(BorderLayout()).apply {
                add(JBLabel("Item Fields (Metadata Only - Zero Secret Values)"), BorderLayout.NORTH)
                add(JBScrollPane(fieldTable), BorderLayout.CENTER)
            }
        }

        val vaultUpperPanel = JPanel(BorderLayout(4, 4)).apply {
            val leftVaults = JPanel(BorderLayout()).apply {
                add(JBLabel("Accessible Vaults"), BorderLayout.NORTH)
                add(JBScrollPane(vaultList), BorderLayout.CENTER)
            }
            val vaultSplit = JBSplitter(false, 0.25f).apply {
                firstComponent = leftVaults
                secondComponent = itemsFieldsSplitter
            }
            add(vaultSplit, BorderLayout.CENTER)
            add(itemActionRow, BorderLayout.SOUTH)
        }

        val syncActionRow = JPanel(FlowLayout(FlowLayout.LEFT, 6, 2)).apply {
            add(JButton("Mark Absent").apply { addActionListener { markSelectedBindingAbsent() } })
            add(JButton("Adopt AWS").apply { addActionListener { adoptSelectedAwsSecret(confirmUnmanaged = false) } })
            add(JButton("Prepare GitHub").apply { addActionListener { prepareGithubTarget() } })
            add(JButton("Preview & Sync...").apply { addActionListener { previewAndApplyPlan() } })
            add(JButton("Render Template...").apply { addActionListener { promptRenderTemplate() } })
        }

        val lowerBindingsPanel = JPanel(BorderLayout(4, 4)).apply {
            add(JBLabel("Manifest Secret Bindings (secretbridge.json)"), BorderLayout.NORTH)
            add(JBScrollPane(bindingsTable), BorderLayout.CENTER)
            add(syncActionRow, BorderLayout.SOUTH)
        }

        val mainVerticalSplitter = JBSplitter(true, 0.55f).apply {
            firstComponent = vaultUpperPanel
            secondComponent = lowerBindingsPanel
        }

        add(topBar, BorderLayout.NORTH)
        add(mainVerticalSplitter, BorderLayout.CENTER)
    }

    override fun dispose() {
        stopCaptureCountdownBanner()
    }

    private fun selectedEnvironment(): String? = envCombo.selectedItem as? String

    private fun updateVaultButtonState(caps: ServiceAccountCapabilities?) {
        currentCapabilities = caps
        val state = VaultUiPolicy.computeCreateVaultButtonState(caps)
        createVaultButton.isEnabled = state.enabled
        createVaultButton.toolTipText = state.tooltip
    }

    private fun refreshVfsManifest() {
        val path = EnclaveClient.getInstance(project).manifestPathOrNull() ?: return
        LocalFileSystem.getInstance().refreshAndFindFileByNioFile(path)?.refresh(true, false)
    }

    private fun reloadManifestAndVaultState() {
        statusBanner.text = "Loading secretbridge.json and querying enclave over E2E Noise_IK..."
        EnclaveClient.runBackgroundTask(
            project = project,
            title = "Refreshing SecretBridge State",
            work = {
                val client = EnclaveClient.getInstance(project)
                val manifestPath = client.requireManifestPath()
                val loadedManifest = try {
                    client.executeHostCommandOffEdt(HostCommand.ManifestLoad(manifestPath)).requireManifest()
                } catch (_: Exception) {
                    null
                }
                val caps = (client.executeEnclaveOffEdt(EnclaveRequest.Capabilities) as? EnclaveResult.Capabilities)
                    ?.capabilities
                val vaults = if (caps?.authenticated == true) {
                    (client.executeEnclaveOffEdt(EnclaveRequest.Vaults) as? EnclaveResult.Vaults)?.vaults.orEmpty()
                } else {
                    emptyList()
                }
                Triple(loadedManifest, caps, vaults)
            },
            onSuccessEdt = { (manifest, caps, vaults) ->
                currentManifest = manifest
                updateVaultButtonState(caps)
                vaultListModel.clear()
                for (v in vaults) {
                    val rw = if (v.writable) "rw" else "ro"
                    vaultListModel.addElement("${v.name} (${v.id}) [$rw]")
                }

                val previousEnv = selectedEnvironment()
                envCombo.removeAllItems()
                if (manifest != null) {
                    val envNames = manifest.environments.keys.sorted()
                    for (envName in envNames) {
                        envCombo.addItem(envName)
                    }
                    if (previousEnv != null && envNames.contains(previousEnv)) {
                        envCombo.selectedItem = previousEnv
                    } else if (envNames.isNotEmpty()) {
                        envCombo.selectedIndex = 0
                    }
                    statusBanner.text = "Loaded project '${manifest.project}' (${envNames.size} environment(s))."
                    onEnvironmentSelectionChanged()
                } else {
                    bindingsTableModel.setRows(emptyList())
                    itemListModel.clear()
                    fieldTableModel.setRows(emptyList())
                    statusBanner.text = "No valid secretbridge.json found. Click 'Init Manifest...' to create one."
                }
            },
            onErrorEdt = { err ->
                statusBanner.text = "Enclave refresh error: ${err.message}"
            },
        )
    }

    private fun onEnvironmentSelectionChanged() {
        val manifest = currentManifest ?: return
        val env = selectedEnvironment() ?: return
        val envCfg = manifest.environments[env] ?: return
        val entries = envCfg.secrets.entries.map { (k, v) -> BindingEntry(k, v) }
        bindingsTableModel.setRows(entries)

        if (currentCapabilities?.authenticated != true) return
        EnclaveClient.runBackgroundTask(
            project = project,
            title = "Loading Vault Items ($env)",
            work = {
                val client = EnclaveClient.getInstance(project)
                (client.executeEnclaveOffEdt(EnclaveRequest.Items(manifest, env)) as? EnclaveResult.Items)
                    ?.items.orEmpty()
            },
            onSuccessEdt = { items ->
                itemListModel.clear()
                items.forEach(itemListModel::addElement)
                fieldTableModel.setRows(emptyList())
            },
            onErrorEdt = { err ->
                statusBanner.text = "Failed loading vault items for '$env': ${err.message}"
            },
        )
    }

    private fun loadFieldsForItem(item: ItemSummary) {
        val manifest = currentManifest ?: return
        val env = selectedEnvironment() ?: return
        EnclaveClient.runBackgroundTask(
            project = project,
            title = "Loading Item Fields (${item.title})",
            work = {
                val client = EnclaveClient.getInstance(project)
                (client.executeEnclaveOffEdt(EnclaveRequest.Fields(manifest, env, item.id)) as? EnclaveResult.Fields)
                    ?.itemFields
            },
            onSuccessEdt = { resp ->
                fieldTableModel.setRows(resp?.fields.orEmpty())
            },
            onErrorEdt = { err ->
                statusBanner.text = "Failed loading fields: ${err.message}"
            },
        )
    }

    private fun promptInitManifest() {
        val projectField = JBTextField(project.name.lowercase().replace(Regex("[^a-z0-9_.-]"), "-").ifEmpty { "app" })
        val accountField = JBTextField("my.1password.com")
        val envField = JBTextField("dev")
        val vaultField = JBTextField("app-dev")

        val dialog = SimpleFormDialog(
            project = project,
            dialogTitle = "Initialize secretbridge.json",
            formPanel = FormBuilder.createFormBuilder()
                .addLabeledComponent("Project slug:", projectField)
                .addLabeledComponent("1Password account:", accountField)
                .addLabeledComponent("Initial environment:", envField)
                .addLabeledComponent("Environment vault name:", vaultField)
                .panel,
        )
        if (!dialog.showAndGet()) return

        val manifest = Manifest(
            version = 2,
            project = projectField.text.trim(),
            account = accountField.text.trim(),
            environments = mapOf(
                envField.text.trim() to EnvironmentConfig(vault = vaultField.text.trim()),
            ),
        )
        EnclaveClient.runBackgroundTask(
            project = project,
            title = "Saving secretbridge.json",
            work = {
                val client = EnclaveClient.getInstance(project)
                client.executeHostCommandOffEdt(
                    HostCommand.ManifestSave(client.requireManifestPath(), manifest),
                ).requireManifest()
            },
            onSuccessEdt = {
                refreshVfsManifest()
                reloadManifestAndVaultState()
            },
            onErrorEdt = { err ->
                Messages.showErrorDialog(project, err.message ?: "Manifest save failed", "SecretBridge Error")
            },
        )
    }

    private fun promptCreateVault() {
        val state = VaultUiPolicy.computeCreateVaultButtonState(currentCapabilities)
        if (!state.enabled) {
            Messages.showWarningDialog(project, state.tooltip, "Vault Creation Restricted")
            return
        }
        val name = Messages.showInputDialog(
            project,
            "New 1Password vault name (Service Account will own this vault):",
            "Create 1Password Vault",
            null,
        )?.trim()
        if (name.isNullOrEmpty()) return

        EnclaveClient.runBackgroundTask(
            project = project,
            title = "Creating Vault '$name'",
            work = {
                val client = EnclaveClient.getInstance(project)
                client.executeEnclaveOffEdt(EnclaveRequest.VaultCreate(name))
            },
            onSuccessEdt = {
                statusBanner.text = "Created 1Password vault '$name'."
                reloadManifestAndVaultState()
            },
            onErrorEdt = { err ->
                Messages.showErrorDialog(project, err.message ?: "Vault creation failed", "SecretBridge Error")
            },
        )
    }

    private fun promptGenerateSecret() {
        val manifest = currentManifest ?: return
        val env = selectedEnvironment() ?: return
        val settings = BridgeSettings.getInstance().state

        val titleField = JBTextField(itemList.selectedValue?.title ?: "")
        val secretNameField = JBTextField("API_SECRET_KEY")
        val lengthSpinner = JSpinner(SpinnerNumberModel(settings.defaultGenerateLength.coerceIn(16, 256), 16, 256, 4))
        val charsetCombo = ComboBox(SecretCharset.entries.toTypedArray()).apply {
            selectedItem = SecretCharset.fromWire(settings.defaultGenerateCharset)
        }
        val autoBindCheck = JBCheckBox("Bind generated op:// reference into secretbridge.json ($env)", true)

        val dialog = SimpleFormDialog(
            project = project,
            dialogTitle = "Generate Secret Inside Enclave (CSPRNG)",
            formPanel = FormBuilder.createFormBuilder()
                .addLabeledComponent("1Password item title:", titleField)
                .addLabeledComponent("Field / Secret Name (A-Z0-9_):", secretNameField)
                .addLabeledComponent("Secret length:", lengthSpinner)
                .addLabeledComponent("Character set:", charsetCombo)
                .addComponent(autoBindCheck)
                .panel,
        )
        if (!dialog.showAndGet()) return

        val itemTitle = titleField.text.trim()
        val secName = secretNameField.text.trim()
        val spec = GenerateSpec(
            length = lengthSpinner.value as Int,
            charset = charsetCombo.selectedItem as? SecretCharset ?: SecretCharset.ALPHANUMERIC_SYMBOLS,
        )
        val selectedExisting = itemList.selectedValue
        val target = if (selectedExisting != null && selectedExisting.title == itemTitle) {
            CaptureTarget.ExistingItemNewField(itemId = selectedExisting.id, fieldName = secName)
        } else {
            CaptureTarget.NewItem(title = itemTitle, fieldName = secName)
        }
        val shouldBind = autoBindCheck.isSelected

        EnclaveClient.runBackgroundTask(
            project = project,
            title = "Generating Secret in Guest Enclave",
            work = {
                val client = EnclaveClient.getInstance(project)
                val stored = client.executeEnclaveOffEdt(
                    EnclaveRequest.GenerateSecret(manifest, env, target, spec),
                ) as? EnclaveResult.SecretStored
                    ?: throw EnclaveBridgeException("internal_error", "Unexpected generate-secret response")
                if (shouldBind) {
                    client.executeHostCommandOffEdt(
                        HostCommand.ManifestBind(
                            manifestPath = client.requireManifestPath(),
                            environment = env,
                            name = secName,
                            ref = stored.receipt.ref,
                        ),
                    ).requireManifest()
                }
                stored.receipt
            },
            onSuccessEdt = { receipt ->
                refreshVfsManifest()
                statusBanner.text = "Generated in-VM secret -> ${receipt.ref} (0% host plaintext exposure)."
                reloadManifestAndVaultState()
            },
            onErrorEdt = { err ->
                Messages.showErrorDialog(project, err.message ?: "Generate secret failed", "SecretBridge Error")
            },
        )
    }

    private fun promptArmedCapture() {
        val manifest = currentManifest ?: run {
            Messages.showInfoMessage(project, "Initialize or load secretbridge.json first.", "SecretBridge")
            return
        }
        val env = selectedEnvironment() ?: return
        val titleField = JBTextField(itemList.selectedValue?.title ?: "")
        val secretNameField = JBTextField("EXTERNAL_API_KEY")
        val autoBindCheck = JBCheckBox("Bind captured op:// reference into secretbridge.json ($env)", true)

        val dialog = SimpleFormDialog(
            project = project,
            dialogTitle = "15-Second Single-Shot Armed Copy Capture",
            formPanel = FormBuilder.createFormBuilder()
                .addComponent(
                    JBLabel(
                        "After clicking OK, switch to the source window and press Cmd+C / Ctrl+C (or click Copy) within 15s.",
                    ),
                )
                .addLabeledComponent("1Password item title:", titleField)
                .addLabeledComponent("Field / Secret Name (A-Z0-9_):", secretNameField)
                .addComponent(autoBindCheck)
                .panel,
        )
        if (!dialog.showAndGet()) return

        val itemTitle = titleField.text.trim()
        val secName = secretNameField.text.trim()
        val selectedExisting = itemList.selectedValue
        val target = if (selectedExisting != null && selectedExisting.title == itemTitle) {
            CaptureTarget.ExistingItemNewField(itemId = selectedExisting.id, fieldName = secName)
        } else {
            CaptureTarget.NewItem(title = itemTitle, fieldName = secName)
        }
        val shouldBind = autoBindCheck.isSelected

        startCaptureCountdownBanner()
        EnclaveClient.runBackgroundTask(
            project = project,
            title = "Armed Copy Capture (15s TTL)",
            work = {
                val client = EnclaveClient.getInstance(project)
                val receipt = client.executeArmedCaptureOffEdt(manifest, env, target)
                if (shouldBind) {
                    client.executeHostCommandOffEdt(
                        HostCommand.ManifestBind(
                            manifestPath = client.requireManifestPath(),
                            environment = env,
                            name = secName,
                            ref = receipt.ref,
                        ),
                    ).requireManifest()
                }
                receipt
            },
            onSuccessEdt = { receipt ->
                stopCaptureCountdownBanner()
                refreshVfsManifest()
                val badge = receipt.interceptMode?.badgeText ?: "Sealed X25519 Capture"
                captureCountdownLabel.text = "Captured [$badge] -> ${receipt.ref}"
                reloadManifestAndVaultState()
            },
            onErrorEdt = { err ->
                stopCaptureCountdownBanner()
                captureCountdownLabel.text = "Armed capture disarmed: ${err.message}"
            },
        )
    }

    private fun startCaptureCountdownBanner() {
        stopCaptureCountdownBanner()
        var secondsLeft = 15
        captureCountdownLabel.text = "ARMED (${secondsLeft}s remaining): Copy external secret now..."
        countdownTimer = Timer(1000) {
            secondsLeft -= 1
            if (secondsLeft > 0) {
                captureCountdownLabel.text = "ARMED (${secondsLeft}s remaining): Copy external secret now..."
            } else {
                stopCaptureCountdownBanner()
            }
        }.also { it.start() }
    }

    private fun stopCaptureCountdownBanner() {
        countdownTimer?.stop()
        countdownTimer = null
    }

    private fun promptBindSelectedField() {
        val env = selectedEnvironment() ?: return
        val row = fieldTable.selectedRow
        val selectedField = fieldTableModel.rowAt(row)
        if (selectedField == null) {
            Messages.showInfoMessage(project, "Select an item field first.", "Bind Secret Reference")
            return
        }
        val suggested = selectedField.label.uppercase().replace(Regex("[^A-Z0-9_]"), "_").trim('_')
            .ifEmpty { "APP_SECRET" }
        val nameField = JBTextField(suggested)
        val ghCheck = JBCheckBox("Sync to GitHub Actions", true)
        val awsCheck = JBCheckBox("Sync to AWS Secrets Manager", true)

        val dialog = SimpleFormDialog(
            project = project,
            dialogTitle = "Bind 1Password Reference (${selectedField.ref})",
            formPanel = FormBuilder.createFormBuilder()
                .addLabeledComponent("Application Secret Name:", nameField)
                .addComponent(ghCheck)
                .addComponent(awsCheck)
                .panel,
        )
        if (!dialog.showAndGet()) return

        val secretName = nameField.text.trim()
        EnclaveClient.runBackgroundTask(
            project = project,
            title = "Binding $secretName",
            work = {
                val client = EnclaveClient.getInstance(project)
                client.executeHostCommandOffEdt(
                    HostCommand.ManifestBind(
                        manifestPath = client.requireManifestPath(),
                        environment = env,
                        name = secretName,
                        ref = selectedField.ref,
                        github = ghCheck.isSelected,
                        aws = awsCheck.isSelected,
                    ),
                ).requireManifest()
            },
            onSuccessEdt = { updated ->
                currentManifest = updated
                refreshVfsManifest()
                onEnvironmentSelectionChanged()
                statusBanner.text = "Bound $secretName -> ${selectedField.ref}."
            },
            onErrorEdt = { err ->
                Messages.showErrorDialog(project, err.message ?: "Bind failed", "SecretBridge Error")
            },
        )
    }

    private fun confirmArchiveSelectedItem() {
        val manifest = currentManifest ?: return
        val env = selectedEnvironment() ?: return
        val selected = itemList.selectedValue ?: return
        val confirm = Messages.showYesNoDialog(
            project,
            "Archive item '${selected.title}' (${selected.category}) in '$env'?",
            "Archive 1Password Item",
            Messages.getQuestionIcon(),
        )
        if (confirm != Messages.YES) return

        EnclaveClient.runBackgroundTask(
            project = project,
            title = "Archiving '${selected.title}'",
            work = {
                EnclaveClient.getInstance(project)
                    .executeEnclaveOffEdt(EnclaveRequest.Archive(manifest, env, selected.id))
            },
            onSuccessEdt = {
                statusBanner.text = "Archived '${selected.title}'."
                onEnvironmentSelectionChanged()
            },
            onErrorEdt = { err ->
                Messages.showErrorDialog(project, err.message ?: "Archive refused", "SecretBridge Error")
            },
        )
    }

    private fun markSelectedBindingAbsent() {
        val env = selectedEnvironment() ?: return
        val selected = bindingsTableModel.rowAt(bindingsTable.selectedRow) ?: return
        EnclaveClient.runBackgroundTask(
            project = project,
            title = "Marking ${selected.name} Absent",
            work = {
                val client = EnclaveClient.getInstance(project)
                client.executeHostCommandOffEdt(
                    HostCommand.ManifestMarkAbsent(client.requireManifestPath(), env, selected.name),
                ).requireManifest()
            },
            onSuccessEdt = { updated ->
                currentManifest = updated
                refreshVfsManifest()
                onEnvironmentSelectionChanged()
                statusBanner.text = "Marked '${selected.name}' absent (will delete from cloud targets on next Apply)."
            },
            onErrorEdt = { err ->
                Messages.showErrorDialog(project, err.message ?: "Update failed", "SecretBridge Error")
            },
        )
    }

    private fun adoptSelectedAwsSecret(confirmUnmanaged: Boolean) {
        val manifest = currentManifest ?: return
        val env = selectedEnvironment() ?: return
        val selected = bindingsTableModel.rowAt(bindingsTable.selectedRow) ?: return
        EnclaveClient.runBackgroundTask(
            project = project,
            title = "Adopting AWS Secret (${selected.name})",
            work = {
                EnclaveClient.getInstance(project).executeEnclaveOffEdt(
                    EnclaveRequest.AdoptAws(
                        manifest = manifest,
                        environment = env,
                        name = selected.name,
                        confirmUnmanaged = confirmUnmanaged,
                    ),
                )
            },
            onSuccessEdt = { res ->
                val msg = (res as? EnclaveResult.AwsAdopted)?.notice ?: "Adopted AWS secret ${selected.name}."
                statusBanner.text = msg
            },
            onErrorEdt = { err ->
                if (!confirmUnmanaged && err is EnclaveBridgeException && err.code == "conflict") {
                    val choice = Messages.showYesNoDialog(
                        project,
                        "${err.message}\n\nConfirm adopting unmanaged AWS secret '${selected.name}' under SecretBridge management?",
                        "Confirm Unmanaged AWS Secret Adoption",
                        Messages.getWarningIcon(),
                    )
                    if (choice == Messages.YES) {
                        adoptSelectedAwsSecret(confirmUnmanaged = true)
                    }
                    return@runBackgroundTask
                }
                Messages.showErrorDialog(project, err.message ?: "AWS adopt failed", "SecretBridge Error")
            },
        )
    }

    private fun prepareGithubTarget() {
        val manifest = currentManifest ?: return
        val env = selectedEnvironment() ?: return
        EnclaveClient.runBackgroundTask(
            project = project,
            title = "Preparing GitHub Target ($env)",
            work = {
                EnclaveClient.getInstance(project)
                    .executeEnclaveOffEdt(EnclaveRequest.PrepareGithub(manifest, env))
            },
            onSuccessEdt = { res ->
                val msg = (res as? EnclaveResult.GithubPrepared)?.notice ?: "Prepared GitHub target for $env."
                statusBanner.text = msg
            },
            onErrorEdt = { err ->
                Messages.showErrorDialog(project, err.message ?: "GitHub prepare failed", "SecretBridge Error")
            },
        )
    }

    private fun previewAndApplyPlan() {
        val manifest = currentManifest ?: return
        val env = selectedEnvironment() ?: return
        EnclaveClient.runBackgroundTask(
            project = project,
            title = "Computing Signed Sync Plan ($env)",
            work = {
                val res = EnclaveClient.getInstance(project)
                    .executeEnclaveOffEdt(EnclaveRequest.Plan(manifest, env))
                (res as? EnclaveResult.Planned)?.signedPlan
                    ?: throw EnclaveBridgeException("internal_error", "Unexpected plan response")
            },
            onSuccessEdt = { signedPlan ->
                showPlanPreviewDialog(manifest, signedPlan)
            },
            onErrorEdt = { err ->
                Messages.showErrorDialog(project, err.message ?: "Plan computation failed", "SecretBridge Error")
            },
        )
    }

    private fun showPlanPreviewDialog(manifest: Manifest, signedPlan: SignedPlan) {
        if (signedPlan.operations.isEmpty()) {
            Messages.showInfoMessage(
                project,
                "Environment '${signedPlan.environment}' has zero pending sync operations.",
                "SecretBridge Sync Plan",
            )
            return
        }
        val summaryText = buildString {
            appendLine("Environment: ${signedPlan.environment}")
            appendLine("Manifest Digest: ${signedPlan.manifestDigest}")
            appendLine("Source Revision Digest: ${signedPlan.sourceRevisionDigest}")
            appendLine("Enclave HMAC-SHA256: ${signedPlan.planMac.take(16)}...")
            appendLine()
            appendLine("Planned Operations (${signedPlan.operations.size}):")
            for (op in signedPlan.operations) {
                appendLine("  - [${op.action.uppercase()}] ${op.name} -> ${op.detail}")
            }
        }
        val area = JBTextArea(summaryText, 14, 72).apply { isEditable = false }
        val dialog = SimpleFormDialog(
            project = project,
            dialogTitle = "Confirm Signed Sync Plan (${signedPlan.environment})",
            formPanel = JBScrollPane(area),
            okActionText = "Apply Signed Plan",
        )
        if (!dialog.showAndGet()) return

        EnclaveClient.runBackgroundTask(
            project = project,
            title = "Applying Signed Sync Plan (${signedPlan.environment})",
            work = {
                val res = EnclaveClient.getInstance(project)
                    .executeEnclaveOffEdt(EnclaveRequest.Apply(manifest, signedPlan))
                (res as? EnclaveResult.Applied)?.report
                    ?: throw EnclaveBridgeException("internal_error", "Unexpected apply response")
            },
            onSuccessEdt = { report ->
                val reportMsg = buildString {
                    appendLine("Complete: ${report.complete}")
                    for (r in report.results) {
                        val state = if (r.succeeded) "OK" else "FAILED (${r.error})"
                        appendLine("  [${r.target.uppercase()}] ${r.action} ${r.name}: $state")
                    }
                    if (report.pending.isNotEmpty()) {
                        appendLine("Pending unapplied operations: ${report.pending.size}")
                    }
                }
                if (report.complete) {
                    Messages.showInfoMessage(project, reportMsg, "SecretBridge Sync Complete")
                } else {
                    Messages.showWarningDialog(project, reportMsg, "SecretBridge Partial Sync Report")
                }
                statusBanner.text = "Sync complete=${report.complete} (${report.results.size} step(s))."
            },
            onErrorEdt = { err ->
                Messages.showErrorDialog(project, err.message ?: "Plan apply failed", "SecretBridge Error")
            },
        )
    }

    private fun promptRenderTemplate() {
        val manifest = currentManifest ?: return
        val env = selectedEnvironment() ?: return
        val settings = BridgeSettings.getInstance().state
        val kindCombo = ComboBox(TemplateKind.entries.toTypedArray())
        val shaField = JBTextField(settings.pinnedLoadSecretsActionSha)

        val dialog = SimpleFormDialog(
            project = project,
            dialogTitle = "Render Secret Reference Template ($env)",
            formPanel = FormBuilder.createFormBuilder()
                .addLabeledComponent("Template format:", kindCombo)
                .addLabeledComponent("1Password Action 40-hex SHA (optional):", shaField)
                .panel,
        )
        if (!dialog.showAndGet()) return

        val selectedKind = kindCombo.selectedItem as? TemplateKind ?: TemplateKind.ENV
        val sha = shaField.text.trim().takeIf { it.isNotEmpty() }

        EnclaveClient.runBackgroundTask(
            project = project,
            title = "Rendering ${selectedKind.displayLabel}",
            work = {
                val res = EnclaveClient.getInstance(project)
                    .executeEnclaveOffEdt(EnclaveRequest.Template(manifest, env, selectedKind, sha))
                (res as? EnclaveResult.TemplateRendered)?.content
                    ?: throw EnclaveBridgeException("internal_error", "Unexpected template response")
            },
            onSuccessEdt = { rendered ->
                val outArea = JBTextArea(rendered, 18, 80).apply { isEditable = false }
                val outDialog = SimpleFormDialog(
                    project = project,
                    dialogTitle = selectedKind.displayLabel,
                    formPanel = JBScrollPane(outArea),
                    okActionText = "Copy Template to Clipboard",
                )
                if (outDialog.showAndGet()) {
                    CopyPasteManager.getInstance().setContents(StringSelection(rendered))
                    statusBanner.text = "Copied ${selectedKind.wireName} reference template to clipboard."
                }
            },
            onErrorEdt = { err ->
                Messages.showErrorDialog(project, err.message ?: "Template render failed", "SecretBridge Error")
            },
        )
    }
}

private class SimpleFormDialog(
    project: Project,
    dialogTitle: String,
    private val formPanel: JComponent,
    okActionText: String = "OK",
) : DialogWrapper(project) {
    init {
        title = dialogTitle
        setOKButtonText(okActionText)
        init()
    }

    override fun createCenterPanel(): JComponent = formPanel
}

private class FieldTableModel : AbstractTableModel() {
    private val columns = arrayOf("Label", "Type", "1Password Reference")
    private var rows: List<FieldSummary> = emptyList()

    fun setRows(newRows: List<FieldSummary>) {
        rows = newRows
        fireTableDataChanged()
    }

    fun rowAt(index: Int): FieldSummary? = rows.getOrNull(index)

    override fun getRowCount(): Int = rows.size
    override fun getColumnCount(): Int = columns.size
    override fun getColumnName(column: Int): String = columns[column]

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
        val r = rows[rowIndex]
        return when (columnIndex) {
            0 -> r.label
            1 -> r.fieldType
            2 -> r.ref
            else -> ""
        }
    }
}

private class BindingsTableModel : AbstractTableModel() {
    private val columns = arrayOf("Secret Name", "State", "1Password op:// Reference", "GitHub", "AWS")
    private var rows: List<BindingEntry> = emptyList()

    fun setRows(newRows: List<BindingEntry>) {
        rows = newRows
        fireTableDataChanged()
    }

    fun rowAt(index: Int): BindingEntry? = rows.getOrNull(index)

    override fun getRowCount(): Int = rows.size
    override fun getColumnCount(): Int = columns.size
    override fun getColumnName(column: Int): String = columns[column]

    override fun getValueAt(rowIndex: Int, columnIndex: Int): Any {
        val r = rows[rowIndex]
        return when (columnIndex) {
            0 -> r.name
            1 -> r.spec.state.wireName
            2 -> r.spec.ref ?: "(absent)"
            3 -> if (r.spec.github) "yes" else "no"
            4 -> if (r.spec.aws) "yes" else "no"
            else -> ""
        }
    }
}
