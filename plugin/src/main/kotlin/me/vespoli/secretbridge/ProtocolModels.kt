package me.vespoli.secretbridge

data class SanitizedError(
    val code: String,
    val message: String,
) {
    companion object {
        fun fromJson(obj: JsonObj): SanitizedError = SanitizedError(
            code = obj.reqStr("code"),
            message = obj.reqStr("message"),
        )
    }
}

class EnclaveBridgeException(
    val code: String,
    override val message: String,
) : RuntimeException("[$code] $message") {
    companion object {
        fun fromSanitized(err: SanitizedError): EnclaveBridgeException =
            EnclaveBridgeException(err.code, err.message)
    }
}

enum class SecretState(val wireName: String) {
    PRESENT("present"),
    ABSENT("absent"),
    ;

    companion object {
        fun fromWire(raw: String?): SecretState = when (raw) {
            null, "present" -> PRESENT
            "absent" -> ABSENT
            else -> throw ProtocolCodecException("Unknown secret state '$raw'")
        }
    }
}

enum class SecretCharset(val wireName: String, val displayLabel: String) {
    ALPHANUMERIC_SYMBOLS("alphanumeric_symbols", "Alphanumeric + Symbols"),
    ALPHANUMERIC("alphanumeric", "Alphanumeric"),
    HEX_LOWER("hex_lower", "Lowercase Hex"),
    BASE64_URL("base64_url", "URL-Safe Base64"),
    ;

    companion object {
        fun fromWire(raw: String?): SecretCharset =
            entries.firstOrNull { it.wireName == raw } ?: ALPHANUMERIC_SYMBOLS
    }
}

enum class TemplateKind(val wireName: String, val displayLabel: String) {
    ENV("env", ".env (1Password op:// references)"),
    WORKFLOW_NATIVE("workflow-native", "GitHub Actions Workflow (Synced Secrets)"),
    WORKFLOW_1PASSWORD("workflow-1password", "GitHub Actions Workflow (1Password SHA-Pinned)"),
    TERRAFORM("terraform", "Terraform (AWS Secrets Manager Data Sources)"),
    CDK("cdk", "AWS CDK TypeScript (ISecret Imports)"),
    CLOUDFORMATION("cloudformation", "AWS CloudFormation (Dynamic References)"),
}

enum class CaptureInterceptMode(val wireName: String, val badgeText: String) {
    ZERO_PASTEBOARD("zero-pasteboard", "Zero-Pasteboard Intercept"),
    PASTEBOARD_FALLBACK("pasteboard-fallback", "1ms Pasteboard Snapshot-Restore Fallback"),
    ;

    companion object {
        fun fromWire(raw: String): CaptureInterceptMode = when (raw) {
            "zero-pasteboard" -> ZERO_PASTEBOARD
            "pasteboard-fallback" -> PASTEBOARD_FALLBACK
            else -> throw ProtocolCodecException("Unknown capture intercept mode '$raw'")
        }
    }
}

data class GenerateSpec(
    val length: Int = 40,
    val charset: SecretCharset = SecretCharset.ALPHANUMERIC_SYMBOLS,
) {
    fun toJson(): JsonObj = JsonObj(
        linkedMapOf(
            "length" to JsonNum(length),
            "charset" to JsonStr(charset.wireName),
        ),
    )
}

sealed interface CaptureTarget {
    fun toJson(): JsonObj

    data class NewItem(
        val title: String,
        val fieldName: String,
        val tags: List<String> = emptyList(),
    ) : CaptureTarget {
        override fun toJson(): JsonObj = JsonObj(
            linkedMapOf(
                "kind" to JsonStr("new_item"),
                "title" to JsonStr(title),
                "field_name" to JsonStr(fieldName),
                "tags" to JsonArr(tags.map(::JsonStr)),
            ),
        )
    }

    data class ExistingItemNewField(
        val itemId: String,
        val fieldName: String,
    ) : CaptureTarget {
        override fun toJson(): JsonObj = JsonObj(
            linkedMapOf(
                "kind" to JsonStr("existing_item_new_field"),
                "item_id" to JsonStr(itemId),
                "field_name" to JsonStr(fieldName),
            ),
        )
    }

    data class ReplaceFieldValue(
        val itemId: String,
        val fieldId: String,
    ) : CaptureTarget {
        override fun toJson(): JsonObj = JsonObj(
            linkedMapOf(
                "kind" to JsonStr("replace_field_value"),
                "item_id" to JsonStr(itemId),
                "field_id" to JsonStr(fieldId),
            ),
        )
    }
}

data class SecretSpec(
    val ref: String? = null,
    val state: SecretState = SecretState.PRESENT,
    val group: String? = null,
    val github: Boolean = true,
    val aws: Boolean = true,
) {
    fun toJson(): JsonObj {
        val m = LinkedHashMap<String, JsonValue>()
        if (ref != null) m["ref"] = JsonStr(ref)
        m["state"] = JsonStr(state.wireName)
        if (group != null) m["group"] = JsonStr(group)
        m["github"] = JsonBool(github)
        m["aws"] = JsonBool(aws)
        return JsonObj(m)
    }

    companion object {
        fun fromJson(obj: JsonObj): SecretSpec = SecretSpec(
            ref = obj.str("ref"),
            state = SecretState.fromWire(obj.str("state")),
            group = obj.str("group"),
            github = obj.bool("github") ?: true,
            aws = obj.bool("aws") ?: true,
        )
    }
}

data class GitHubTarget(
    val scope: String,
    val host: String = "github.com",
    val repository: String? = null,
    val organization: String? = null,
    val environment: String? = null,
    val repositories: List<String>? = null,
) {
    fun toJson(): JsonObj {
        val m = LinkedHashMap<String, JsonValue>()
        m["scope"] = JsonStr(scope)
        m["host"] = JsonStr(host)
        if (repository != null) m["repository"] = JsonStr(repository)
        if (organization != null) m["organization"] = JsonStr(organization)
        if (environment != null) m["environment"] = JsonStr(environment)
        if (repositories != null) m["repositories"] = JsonArr(repositories.map(::JsonStr))
        return JsonObj(m)
    }

    companion object {
        fun fromJson(obj: JsonObj): GitHubTarget = GitHubTarget(
            scope = obj.reqStr("scope"),
            host = obj.str("host") ?: "github.com",
            repository = obj.str("repository"),
            organization = obj.str("organization"),
            environment = obj.str("environment"),
            repositories = obj.arr("repositories")?.map {
                (it as? JsonStr)?.value ?: throw ProtocolCodecException("Invalid repository slug")
            },
        )
    }
}

data class AwsTarget(
    val profile: String? = null,
    val region: String,
    val accountId: String,
    val prefix: String,
    val kmsKeyId: String? = null,
    val recoveryDays: Int = 30,
) {
    fun toJson(): JsonObj {
        val m = LinkedHashMap<String, JsonValue>()
        if (profile != null) m["profile"] = JsonStr(profile)
        m["region"] = JsonStr(region)
        m["account_id"] = JsonStr(accountId)
        m["prefix"] = JsonStr(prefix)
        if (kmsKeyId != null) m["kms_key_id"] = JsonStr(kmsKeyId)
        m["recovery_days"] = JsonNum(recoveryDays)
        return JsonObj(m)
    }

    companion object {
        fun fromJson(obj: JsonObj): AwsTarget = AwsTarget(
            profile = obj.str("profile"),
            region = obj.reqStr("region"),
            accountId = obj.reqStr("account_id"),
            prefix = obj.reqStr("prefix"),
            kmsKeyId = obj.str("kms_key_id"),
            recoveryDays = obj.int("recovery_days") ?: 30,
        )
    }
}

data class EnvironmentConfig(
    val vault: String,
    val secrets: Map<String, SecretSpec> = emptyMap(),
    val github: GitHubTarget? = null,
    val aws: AwsTarget? = null,
) {
    fun toJson(): JsonObj {
        val m = LinkedHashMap<String, JsonValue>()
        m["vault"] = JsonStr(vault)
        val secretsMap = LinkedHashMap<String, JsonValue>()
        for ((k, v) in secrets.toSortedMap()) {
            secretsMap[k] = v.toJson()
        }
        m["secrets"] = JsonObj(secretsMap)
        if (github != null) m["github"] = github.toJson()
        if (aws != null) m["aws"] = aws.toJson()
        return JsonObj(m)
    }

    companion object {
        fun fromJson(obj: JsonObj): EnvironmentConfig {
            val secretsObj = obj.obj("secrets")
            val secrets = LinkedHashMap<String, SecretSpec>()
            if (secretsObj != null) {
                for ((name, rawSpec) in secretsObj.entries) {
                    val specObj = rawSpec as? JsonObj
                        ?: throw ProtocolCodecException("Expected object for secret '$name'")
                    secrets[name] = SecretSpec.fromJson(specObj)
                }
            }
            return EnvironmentConfig(
                vault = obj.reqStr("vault"),
                secrets = secrets,
                github = obj.obj("github")?.let(GitHubTarget::fromJson),
                aws = obj.obj("aws")?.let(AwsTarget::fromJson),
            )
        }
    }
}

data class Manifest(
    val version: Int = 2,
    val project: String,
    val account: String,
    val environments: Map<String, EnvironmentConfig>,
) {
    fun toJson(): JsonObj {
        val envMap = LinkedHashMap<String, JsonValue>()
        for ((name, cfg) in environments.toSortedMap()) {
            envMap[name] = cfg.toJson()
        }
        return JsonObj(
            linkedMapOf(
                "version" to JsonNum(version),
                "project" to JsonStr(project),
                "account" to JsonStr(account),
                "environments" to JsonObj(envMap),
            ),
        )
    }

    companion object {
        fun fromJson(obj: JsonObj): Manifest {
            if (obj.entries.containsKey("tools")) {
                throw ProtocolCodecException("Legacy 'tools' execution block is forbidden in SecretBridge manifests")
            }
            val envsObj = obj.reqObj("environments")
            val envs = LinkedHashMap<String, EnvironmentConfig>()
            for ((envName, rawEnv) in envsObj.entries) {
                val envObj = rawEnv as? JsonObj
                    ?: throw ProtocolCodecException("Expected object for environment '$envName'")
                envs[envName] = EnvironmentConfig.fromJson(envObj)
            }
            return Manifest(
                version = obj.reqInt("version"),
                project = obj.reqStr("project"),
                account = obj.reqStr("account"),
                environments = envs,
            )
        }
    }
}

/**
 * Write-only bootstrap credentials backed by mutable [CharArray]s.
 * Every array is zeroized during JSON serialization or [wipe].
 */
class SessionCredentialsChars(
    val opServiceAccountToken: CharArray? = null,
    val githubToken: CharArray? = null,
    val awsAccessKeyId: CharArray? = null,
    val awsSecretAccessKey: CharArray? = null,
    val awsSessionToken: CharArray? = null,
) {
    fun isEmpty(): Boolean =
        (opServiceAccountToken == null || opServiceAccountToken.isEmpty()) &&
            (githubToken == null || githubToken.isEmpty()) &&
            (awsAccessKeyId == null || awsAccessKeyId.isEmpty()) &&
            (awsSecretAccessKey == null || awsSecretAccessKey.isEmpty()) &&
            (awsSessionToken == null || awsSessionToken.isEmpty())

    fun toJson(): JsonObj {
        val m = LinkedHashMap<String, JsonValue>()
        if (opServiceAccountToken != null && opServiceAccountToken.isNotEmpty()) {
            m["op_service_account_token"] = JsonSecretChars(opServiceAccountToken)
        } else {
            opServiceAccountToken?.fill('\u0000')
        }
        if (githubToken != null && githubToken.isNotEmpty()) {
            m["github_token"] = JsonSecretChars(githubToken)
        } else {
            githubToken?.fill('\u0000')
        }
        if (awsAccessKeyId != null && awsAccessKeyId.isNotEmpty()) {
            m["aws_access_key_id"] = JsonSecretChars(awsAccessKeyId)
        } else {
            awsAccessKeyId?.fill('\u0000')
        }
        if (awsSecretAccessKey != null && awsSecretAccessKey.isNotEmpty()) {
            m["aws_secret_access_key"] = JsonSecretChars(awsSecretAccessKey)
        } else {
            awsSecretAccessKey?.fill('\u0000')
        }
        if (awsSessionToken != null && awsSessionToken.isNotEmpty()) {
            m["aws_session_token"] = JsonSecretChars(awsSessionToken)
        } else {
            awsSessionToken?.fill('\u0000')
        }
        return JsonObj(m)
    }

    fun wipe() {
        opServiceAccountToken?.fill('\u0000')
        githubToken?.fill('\u0000')
        awsAccessKeyId?.fill('\u0000')
        awsSecretAccessKey?.fill('\u0000')
        awsSessionToken?.fill('\u0000')
    }
}

sealed interface EnclaveRequest {
    fun toJson(): JsonObj

    class ConfigureSession(private val credentials: SessionCredentialsChars) : EnclaveRequest {
        override fun toJson(): JsonObj = JsonObj(
            linkedMapOf(
                "action" to JsonStr("configure-session"),
                "credentials" to credentials.toJson(),
            ),
        )
    }

    data object Capabilities : EnclaveRequest {
        override fun toJson(): JsonObj = JsonObj(mapOf("action" to JsonStr("capabilities")))
    }

    data class Doctor(val manifest: Manifest? = null) : EnclaveRequest {
        override fun toJson(): JsonObj {
            val m = LinkedHashMap<String, JsonValue>()
            m["action"] = JsonStr("doctor")
            if (manifest != null) m["manifest"] = manifest.toJson()
            return JsonObj(m)
        }
    }

    data class ValidateConfig(val config: Manifest) : EnclaveRequest {
        override fun toJson(): JsonObj = JsonObj(
            linkedMapOf(
                "action" to JsonStr("validate-config"),
                "config" to config.toJson(),
            ),
        )
    }

    data object Vaults : EnclaveRequest {
        override fun toJson(): JsonObj = JsonObj(mapOf("action" to JsonStr("vaults")))
    }

    data class VaultCreate(val name: String) : EnclaveRequest {
        override fun toJson(): JsonObj = JsonObj(
            linkedMapOf(
                "action" to JsonStr("vault-create"),
                "name" to JsonStr(name),
            ),
        )
    }

    data class Items(val manifest: Manifest, val environment: String) : EnclaveRequest {
        override fun toJson(): JsonObj = JsonObj(
            linkedMapOf(
                "action" to JsonStr("items"),
                "manifest" to manifest.toJson(),
                "environment" to JsonStr(environment),
            ),
        )
    }

    data class Fields(
        val manifest: Manifest,
        val environment: String,
        val item: String,
    ) : EnclaveRequest {
        override fun toJson(): JsonObj = JsonObj(
            linkedMapOf(
                "action" to JsonStr("fields"),
                "manifest" to manifest.toJson(),
                "environment" to JsonStr(environment),
                "item" to JsonStr(item),
            ),
        )
    }

    data class GenerateSecret(
        val manifest: Manifest,
        val environment: String,
        val target: CaptureTarget,
        val spec: GenerateSpec = GenerateSpec(),
    ) : EnclaveRequest {
        override fun toJson(): JsonObj = JsonObj(
            linkedMapOf(
                "action" to JsonStr("generate-secret"),
                "manifest" to manifest.toJson(),
                "environment" to JsonStr(environment),
                "target" to target.toJson(),
                "spec" to spec.toJson(),
            ),
        )
    }

    data class EditMetadata(
        val manifest: Manifest,
        val environment: String,
        val item: String,
        val title: String? = null,
        val tags: List<String>? = null,
        val removeFieldId: String? = null,
    ) : EnclaveRequest {
        override fun toJson(): JsonObj {
            val m = LinkedHashMap<String, JsonValue>()
            m["action"] = JsonStr("edit-metadata")
            m["manifest"] = manifest.toJson()
            m["environment"] = JsonStr(environment)
            m["item"] = JsonStr(item)
            if (title != null) m["title"] = JsonStr(title)
            if (tags != null) m["tags"] = JsonArr(tags.map(::JsonStr))
            if (removeFieldId != null) m["remove_field_id"] = JsonStr(removeFieldId)
            return JsonObj(m)
        }
    }

    data class Archive(
        val manifest: Manifest,
        val environment: String,
        val item: String,
    ) : EnclaveRequest {
        override fun toJson(): JsonObj = JsonObj(
            linkedMapOf(
                "action" to JsonStr("archive"),
                "manifest" to manifest.toJson(),
                "environment" to JsonStr(environment),
                "item" to JsonStr(item),
            ),
        )
    }

    data class Move(
        val manifest: Manifest,
        val environment: String,
        val item: String,
        val destination: String,
    ) : EnclaveRequest {
        override fun toJson(): JsonObj = JsonObj(
            linkedMapOf(
                "action" to JsonStr("move"),
                "manifest" to manifest.toJson(),
                "environment" to JsonStr(environment),
                "item" to JsonStr(item),
                "destination" to JsonStr(destination),
            ),
        )
    }

    data class Bindings(val manifest: Manifest, val environment: String) : EnclaveRequest {
        override fun toJson(): JsonObj = JsonObj(
            linkedMapOf(
                "action" to JsonStr("bindings"),
                "manifest" to manifest.toJson(),
                "environment" to JsonStr(environment),
            ),
        )
    }

    data class AdoptAws(
        val manifest: Manifest,
        val environment: String,
        val name: String,
    ) : EnclaveRequest {
        override fun toJson(): JsonObj = JsonObj(
            linkedMapOf(
                "action" to JsonStr("adopt-aws"),
                "manifest" to manifest.toJson(),
                "environment" to JsonStr(environment),
                "name" to JsonStr(name),
            ),
        )
    }

    data class PrepareGithub(val manifest: Manifest, val environment: String) : EnclaveRequest {
        override fun toJson(): JsonObj = JsonObj(
            linkedMapOf(
                "action" to JsonStr("prepare-github"),
                "manifest" to manifest.toJson(),
                "environment" to JsonStr(environment),
            ),
        )
    }

    data class Plan(val manifest: Manifest, val environment: String) : EnclaveRequest {
        override fun toJson(): JsonObj = JsonObj(
            linkedMapOf(
                "action" to JsonStr("plan"),
                "manifest" to manifest.toJson(),
                "environment" to JsonStr(environment),
            ),
        )
    }

    data class Apply(val manifest: Manifest, val signedPlan: SignedPlan) : EnclaveRequest {
        override fun toJson(): JsonObj = JsonObj(
            linkedMapOf(
                "action" to JsonStr("apply"),
                "manifest" to manifest.toJson(),
                "signed_plan" to signedPlan.toJson(),
            ),
        )
    }

    data class Template(
        val manifest: Manifest,
        val environment: String,
        val kind: TemplateKind,
        val actionSha: String? = null,
    ) : EnclaveRequest {
        override fun toJson(): JsonObj {
            val m = LinkedHashMap<String, JsonValue>()
            m["action"] = JsonStr("template")
            m["manifest"] = manifest.toJson()
            m["environment"] = JsonStr(environment)
            m["kind"] = JsonStr(kind.wireName)
            if (!actionSha.isNullOrBlank()) m["action_sha"] = JsonStr(actionSha)
            return JsonObj(m)
        }
    }
}

sealed interface HostCommand {
    fun toJson(): JsonObj

    data class Enclave(val request: EnclaveRequest) : HostCommand {
        override fun toJson(): JsonObj = JsonObj(
            linkedMapOf(
                "host_op" to JsonStr("enclave"),
                "request" to request.toJson(),
            ),
        )
    }

    data class ArmedCapture(
        val manifestPath: String,
        val environment: String,
        val target: CaptureTarget,
    ) : HostCommand {
        override fun toJson(): JsonObj = JsonObj(
            linkedMapOf(
                "host_op" to JsonStr("armed-capture"),
                "manifest_path" to JsonStr(manifestPath),
                "environment" to JsonStr(environment),
                "target" to target.toJson(),
            ),
        )
    }

    data class ManifestLoad(val manifestPath: String) : HostCommand {
        override fun toJson(): JsonObj = JsonObj(
            linkedMapOf(
                "host_op" to JsonStr("manifest-load"),
                "manifest_path" to JsonStr(manifestPath),
            ),
        )
    }

    data class ManifestSave(val manifestPath: String, val manifest: Manifest) : HostCommand {
        override fun toJson(): JsonObj = JsonObj(
            linkedMapOf(
                "host_op" to JsonStr("manifest-save"),
                "manifest_path" to JsonStr(manifestPath),
                "manifest" to manifest.toJson(),
            ),
        )
    }

    data class ManifestBind(
        val manifestPath: String,
        val environment: String,
        val name: String,
        val ref: String,
        val group: String? = null,
        val github: Boolean? = null,
        val aws: Boolean? = null,
    ) : HostCommand {
        override fun toJson(): JsonObj {
            val m = LinkedHashMap<String, JsonValue>()
            m["host_op"] = JsonStr("manifest-bind")
            m["manifest_path"] = JsonStr(manifestPath)
            m["environment"] = JsonStr(environment)
            m["name"] = JsonStr(name)
            m["ref"] = JsonStr(ref)
            if (group != null) m["group"] = JsonStr(group)
            if (github != null) m["github"] = JsonBool(github)
            if (aws != null) m["aws"] = JsonBool(aws)
            return JsonObj(m)
        }
    }

    data class ManifestMarkAbsent(
        val manifestPath: String,
        val environment: String,
        val name: String,
    ) : HostCommand {
        override fun toJson(): JsonObj = JsonObj(
            linkedMapOf(
                "host_op" to JsonStr("manifest-mark-absent"),
                "manifest_path" to JsonStr(manifestPath),
                "environment" to JsonStr(environment),
                "name" to JsonStr(name),
            ),
        )
    }
}

class AuthenticatedHostEnvelope(
    private val authTokenChars: CharArray,
    val command: HostCommand,
) {
    fun toJson(): JsonObj = JsonObj(
        linkedMapOf(
            "auth_token_hex" to JsonSecretChars(authTokenChars.copyOf()),
            "command" to command.toJson(),
        ),
    )
}

data class ServiceAccountCapabilities(
    val authenticated: Boolean,
    val canCreateVaults: Boolean,
    val accessibleVaultIds: List<String>,
    val readOnlyVaultIds: List<String>,
    val notice: String,
) {
    companion object {
        fun fromJson(obj: JsonObj): ServiceAccountCapabilities = ServiceAccountCapabilities(
            authenticated = obj.reqBool("authenticated"),
            canCreateVaults = obj.reqBool("can_create_vaults"),
            accessibleVaultIds = obj.strList("accessible_vault_ids"),
            readOnlyVaultIds = obj.strList("read_only_vault_ids"),
            notice = obj.reqStr("notice"),
        )
    }
}

data class VaultSummary(
    val id: String,
    val name: String,
    val writable: Boolean,
    val createdByServiceAccount: Boolean,
) {
    companion object {
        fun fromJson(obj: JsonObj): VaultSummary = VaultSummary(
            id = obj.reqStr("id"),
            name = obj.reqStr("name"),
            writable = obj.reqBool("writable"),
            createdByServiceAccount = obj.reqBool("created_by_service_account"),
        )
    }
}

data class ItemSummary(
    val id: String,
    val title: String,
    val category: String,
    val tags: List<String>,
) {
    companion object {
        fun fromJson(obj: JsonObj): ItemSummary = ItemSummary(
            id = obj.reqStr("id"),
            title = obj.reqStr("title"),
            category = obj.reqStr("category"),
            tags = obj.strList("tags"),
        )
    }
}

data class FieldSummary(
    val id: String,
    val label: String,
    val fieldType: String,
    val ref: String,
) {
    companion object {
        fun fromJson(obj: JsonObj): FieldSummary = FieldSummary(
            id = obj.reqStr("id"),
            label = obj.reqStr("label"),
            fieldType = obj.reqStr("field_type"),
            ref = obj.reqStr("ref"),
        )
    }
}

data class ItemFieldsResponse(
    val id: String,
    val title: String,
    val category: String,
    val tags: List<String>,
    val fields: List<FieldSummary>,
) {
    companion object {
        fun fromJson(obj: JsonObj): ItemFieldsResponse = ItemFieldsResponse(
            id = obj.reqStr("id"),
            title = obj.reqStr("title"),
            category = obj.reqStr("category"),
            tags = obj.strList("tags"),
            fields = obj.reqArr("fields").map {
                FieldSummary.fromJson(it as? JsonObj ?: throw ProtocolCodecException("Invalid field entry"))
            },
        )
    }
}

data class SecretMutationReceipt(
    val itemId: String,
    val title: String,
    val fieldId: String,
    val ref: String,
    val interceptMode: CaptureInterceptMode?,
) {
    companion object {
        fun fromJson(obj: JsonObj): SecretMutationReceipt = SecretMutationReceipt(
            itemId = obj.reqStr("item_id"),
            title = obj.reqStr("title"),
            fieldId = obj.reqStr("field_id"),
            ref = obj.reqStr("ref"),
            interceptMode = obj.str("intercept_mode")?.let(CaptureInterceptMode::fromWire),
        )
    }
}

data class DoctorEntry(
    val subsystem: String,
    val status: String,
    val detail: String?,
) {
    companion object {
        fun fromJson(obj: JsonObj): DoctorEntry = DoctorEntry(
            subsystem = obj.reqStr("subsystem"),
            status = obj.reqStr("status"),
            detail = obj.str("detail"),
        )
    }
}

data class BindingEntry(
    val name: String,
    val spec: SecretSpec,
) {
    companion object {
        fun fromJson(obj: JsonObj): BindingEntry = BindingEntry(
            name = obj.reqStr("name"),
            spec = SecretSpec.fromJson(obj.reqObj("spec")),
        )
    }
}

data class PlannedOpSummary(
    val target: String,
    val name: String,
    val action: String,
    val detail: String,
) {
    companion object {
        fun fromJson(obj: JsonObj): PlannedOpSummary {
            val target = obj.reqStr("target")
            val name = obj.reqStr("name")
            val action = obj.reqStr("action")
            val detail = when (target) {
                "github" -> {
                    val dest = obj.reqObj("destination")
                    val scope = dest.reqStr("scope")
                    val loc = dest.str("repository") ?: dest.str("organization") ?: scope
                    val envSuffix = dest.str("environment")?.let { " ($it)" } ?: ""
                    "GitHub $scope: $loc$envSuffix"
                }
                "aws" -> {
                    val resource = obj.str("resource") ?: ""
                    val dest = obj.obj("destination")
                    val region = dest?.str("region") ?: ""
                    "AWS Secrets Manager ($region): $resource"
                }
                else -> target
            }
            return PlannedOpSummary(target = target, name = name, action = action, detail = detail)
        }
    }
}

data class SignedPlan(
    val environment: String,
    val manifestDigest: String,
    val sourceRevisionDigest: String,
    val issuedAtUnixSecs: Long,
    val operations: List<PlannedOpSummary>,
    val planMac: String,
    private val rawPlanJson: JsonObj,
) {
    fun toJson(): JsonObj = JsonObj(
        linkedMapOf(
            "plan" to rawPlanJson,
            "plan_mac" to JsonStr(planMac),
        ),
    )

    companion object {
        fun fromJson(obj: JsonObj): SignedPlan {
            val planObj = obj.reqObj("plan")
            val ops = planObj.reqArr("operations").map {
                PlannedOpSummary.fromJson(
                    it as? JsonObj ?: throw ProtocolCodecException("Invalid planned operation"),
                )
            }
            return SignedPlan(
                environment = planObj.reqStr("environment"),
                manifestDigest = planObj.reqStr("manifest_digest"),
                sourceRevisionDigest = planObj.reqStr("source_revision_digest"),
                issuedAtUnixSecs = planObj.reqLong("issued_at_unix_secs"),
                operations = ops,
                planMac = obj.reqStr("plan_mac"),
                rawPlanJson = planObj,
            )
        }
    }
}

data class OpStepResult(
    val target: String,
    val name: String,
    val action: String,
    val succeeded: Boolean,
    val error: String?,
) {
    companion object {
        fun fromJson(obj: JsonObj): OpStepResult = OpStepResult(
            target = obj.reqStr("target"),
            name = obj.reqStr("name"),
            action = obj.reqStr("action"),
            succeeded = obj.reqBool("succeeded"),
            error = obj.str("error"),
        )
    }
}

data class ApplyReport(
    val complete: Boolean,
    val results: List<OpStepResult>,
    val pending: List<PlannedOpSummary>,
) {
    companion object {
        fun fromJson(obj: JsonObj): ApplyReport = ApplyReport(
            complete = obj.reqBool("complete"),
            results = obj.reqArr("results").map {
                OpStepResult.fromJson(it as? JsonObj ?: throw ProtocolCodecException("Invalid step result"))
            },
            pending = obj.reqArr("pending").map {
                PlannedOpSummary.fromJson(it as? JsonObj ?: throw ProtocolCodecException("Invalid pending op"))
            },
        )
    }
}

sealed interface EnclaveResult {
    data class SessionConfigured(
        val hasOpToken: Boolean,
        val hasGithubToken: Boolean,
        val hasAwsCredentials: Boolean,
    ) : EnclaveResult

    data class Capabilities(val capabilities: ServiceAccountCapabilities) : EnclaveResult
    data class Doctor(val entries: List<DoctorEntry>) : EnclaveResult
    data class ConfigValid(val valid: Boolean, val manifestDigest: String) : EnclaveResult
    data class Vaults(val vaults: List<VaultSummary>) : EnclaveResult
    data class VaultCreated(val vault: VaultSummary) : EnclaveResult
    data class Items(val items: List<ItemSummary>) : EnclaveResult
    data class Fields(val itemFields: ItemFieldsResponse) : EnclaveResult
    data class SecretStored(val receipt: SecretMutationReceipt) : EnclaveResult
    data class ItemUpdated(val id: String, val title: String) : EnclaveResult
    data class ItemArchived(val archived: String) : EnclaveResult
    data class ItemMoved(
        val moved: String,
        val newItemId: String,
        val destination: String,
        val notice: String,
    ) : EnclaveResult
    data class Bindings(val bindings: List<BindingEntry>) : EnclaveResult
    data class AwsAdopted(val adopted: String, val notice: String) : EnclaveResult
    data class GithubPrepared(val prepared: String, val notice: String) : EnclaveResult
    data class Planned(val signedPlan: SignedPlan) : EnclaveResult
    data class Applied(val report: ApplyReport) : EnclaveResult
    data class TemplateRendered(val content: String) : EnclaveResult

    companion object {
        fun fromJson(obj: JsonObj): EnclaveResult = when (val kind = obj.reqStr("kind")) {
            "session-configured" -> SessionConfigured(
                hasOpToken = obj.reqBool("has_op_token"),
                hasGithubToken = obj.reqBool("has_github_token"),
                hasAwsCredentials = obj.reqBool("has_aws_credentials"),
            )
            "capabilities" -> Capabilities(ServiceAccountCapabilities.fromJson(obj))
            "doctor" -> Doctor(
                entries = obj.reqArr("entries").map {
                    DoctorEntry.fromJson(it as? JsonObj ?: throw ProtocolCodecException("Invalid doctor entry"))
                },
            )
            "config-valid" -> ConfigValid(
                valid = obj.reqBool("valid"),
                manifestDigest = obj.reqStr("manifest_digest"),
            )
            "vaults" -> Vaults(
                vaults = obj.reqArr("vaults").map {
                    VaultSummary.fromJson(it as? JsonObj ?: throw ProtocolCodecException("Invalid vault entry"))
                },
            )
            "vault-created" -> VaultCreated(VaultSummary.fromJson(obj))
            "items" -> Items(
                items = obj.reqArr("items").map {
                    ItemSummary.fromJson(it as? JsonObj ?: throw ProtocolCodecException("Invalid item entry"))
                },
            )
            "fields" -> Fields(ItemFieldsResponse.fromJson(obj))
            "secret-stored" -> SecretStored(SecretMutationReceipt.fromJson(obj))
            "item-updated" -> ItemUpdated(id = obj.reqStr("id"), title = obj.reqStr("title"))
            "item-archived" -> ItemArchived(archived = obj.reqStr("archived"))
            "item-moved" -> ItemMoved(
                moved = obj.reqStr("moved"),
                newItemId = obj.reqStr("new_item_id"),
                destination = obj.reqStr("destination"),
                notice = obj.reqStr("notice"),
            )
            "bindings" -> Bindings(
                bindings = obj.reqArr("bindings").map {
                    BindingEntry.fromJson(it as? JsonObj ?: throw ProtocolCodecException("Invalid binding entry"))
                },
            )
            "aws-adopted" -> AwsAdopted(
                adopted = obj.reqStr("adopted"),
                notice = obj.reqStr("notice"),
            )
            "github-prepared" -> GithubPrepared(
                prepared = obj.reqStr("prepared"),
                notice = obj.reqStr("notice"),
            )
            "planned" -> Planned(SignedPlan.fromJson(obj))
            "applied" -> Applied(ApplyReport.fromJson(obj))
            "template-rendered" -> TemplateRendered(content = obj.reqStr("content"))
            else -> throw ProtocolCodecException("Unsupported enclave result kind '$kind'")
        }
    }
}

data class EnclaveResponse(
    val ok: Boolean,
    val result: EnclaveResult?,
    val error: SanitizedError?,
) {
    companion object {
        fun fromJson(obj: JsonObj): EnclaveResponse = EnclaveResponse(
            ok = obj.reqBool("ok"),
            result = obj.obj("result")?.let(EnclaveResult::fromJson),
            error = obj.obj("error")?.let(SanitizedError::fromJson),
        )
    }
}

data class HostResponse(
    val ok: Boolean,
    val enclave: EnclaveResponse?,
    val manifest: Manifest?,
    val error: SanitizedError?,
) {
    fun requireEnclaveResult(): EnclaveResult {
        if (!ok) {
            val err = error ?: enclave?.error ?: SanitizedError("unknown", "Host bridge command failed")
            throw EnclaveBridgeException.fromSanitized(err)
        }
        val enc = enclave ?: throw EnclaveBridgeException("transport_failure", "Missing enclave payload")
        if (!enc.ok) {
            val err = enc.error ?: SanitizedError("unknown", "Enclave request failed")
            throw EnclaveBridgeException.fromSanitized(err)
        }
        return enc.result ?: throw EnclaveBridgeException("transport_failure", "Missing enclave result")
    }

    fun requireManifest(): Manifest {
        if (!ok) {
            val err = error ?: SanitizedError("manifest_io", "Manifest operation failed")
            throw EnclaveBridgeException.fromSanitized(err)
        }
        return manifest ?: throw EnclaveBridgeException("manifest_io", "Missing manifest in host response")
    }

    companion object {
        fun fromJson(obj: JsonObj): HostResponse = HostResponse(
            ok = obj.reqBool("ok"),
            enclave = obj.obj("enclave")?.let(EnclaveResponse::fromJson),
            manifest = obj.obj("manifest")?.let(Manifest::fromJson),
            error = obj.obj("error")?.let(SanitizedError::fromJson),
        )
    }
}
