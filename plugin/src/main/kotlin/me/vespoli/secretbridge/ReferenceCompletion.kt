package me.vespoli.secretbridge

import com.intellij.codeInsight.completion.CompletionContributor
import com.intellij.codeInsight.completion.CompletionParameters
import com.intellij.codeInsight.completion.CompletionProvider
import com.intellij.codeInsight.completion.CompletionResultSet
import com.intellij.codeInsight.completion.CompletionType
import com.intellij.codeInsight.lookup.LookupElementBuilder
import com.intellij.openapi.diagnostic.ControlFlowException
import com.intellij.openapi.project.DumbAware
import com.intellij.openapi.project.Project
import com.intellij.openapi.vfs.LocalFileSystem
import com.intellij.openapi.vfs.VFileProperty
import com.intellij.patterns.PlatformPatterns
import com.intellij.util.ProcessingContext
import java.nio.charset.StandardCharsets
import java.util.concurrent.ConcurrentHashMap

data class SecretCompletionItem(
    val secretName: String,
    val opRef: String,
    val environments: List<String>,
)

object ManifestCompletionIndex {
    const val MAX_MANIFEST_BYTES: Long = 256 * 1024

    private val ALLOWED_EXTENSIONS = setOf(
        "env",
        "yml",
        "yaml",
        "json",
        "toml",
        "tf",
        "tfvars",
        "properties",
        "conf",
        "kt",
        "kts",
        "java",
        "rs",
        "go",
        "py",
        "ts",
        "tsx",
        "js",
        "jsx",
        "sh",
    )

    fun isEligibleFileName(fileName: String): Boolean {
        val lower = fileName.lowercase()
        if (lower == "secretbridge.json") return false
        if (lower == ".env" || lower.startsWith(".env.")) return true
        val dot = lower.lastIndexOf('.')
        if (dot < 0 || dot == lower.length - 1) return false
        val ext = lower.substring(dot + 1)
        return ext in ALLOWED_EXTENSIONS
    }

    fun parsePresentBindings(manifestText: String): List<SecretCompletionItem> {
        val manifest = Manifest.fromJson(JsonCodec.parseObject(manifestText))
        val grouped = LinkedHashMap<Pair<String, String>, MutableList<String>>()
        for ((envName, envCfg) in manifest.environments.toSortedMap()) {
            for ((secretName, spec) in envCfg.secrets.toSortedMap()) {
                if (spec.state == SecretState.PRESENT && !spec.ref.isNullOrBlank()) {
                    grouped.getOrPut(secretName to spec.ref) { ArrayList() }.add(envName)
                }
            }
        }
        return grouped.entries.map { (pair, envs) ->
            SecretCompletionItem(
                secretName = pair.first,
                opRef = pair.second,
                environments = envs,
            )
        }
    }
}

class ReferenceCompletionContributor : CompletionContributor(), DumbAware {
    private data class CachedSnapshot(
        val modificationStamp: Long,
        val timeStamp: Long,
        val items: List<SecretCompletionItem>,
    )

    private val cacheByProjectPath = ConcurrentHashMap<String, CachedSnapshot>()

    init {
        extend(
            CompletionType.BASIC,
            PlatformPatterns.psiElement(),
            object : CompletionProvider<CompletionParameters>() {
                override fun addCompletions(
                    parameters: CompletionParameters,
                    context: ProcessingContext,
                    result: CompletionResultSet,
                ) {
                    val editedFile = parameters.originalFile.virtualFile ?: return
                    if (!ManifestCompletionIndex.isEligibleFileName(editedFile.name)) return

                    val project = parameters.originalFile.project
                    val items = loadCachedItemsFromVfs(project)
                    if (items.isEmpty()) return

                    for (item in items) {
                        val envLabel = item.environments.joinToString(",")
                        result.addElement(
                            LookupElementBuilder.create(item.secretName)
                                .withTypeText("SecretBridge [$envLabel]", true)
                                .withTailText(" -> ${item.opRef}", true),
                        )
                        result.addElement(
                            LookupElementBuilder.create(item.opRef)
                                .withLookupString(item.secretName)
                                .withTypeText("${item.secretName} [$envLabel]", true),
                        )
                    }
                }
            },
        )
    }

    private fun loadCachedItemsFromVfs(project: Project): List<SecretCompletionItem> {
        val basePath = project.basePath ?: return emptyList()
        val manifestPath = "$basePath/secretbridge.json"
        val vf = LocalFileSystem.getInstance().findFileByPath(manifestPath) ?: return emptyList()
        if (!vf.isValid || vf.isDirectory || vf.`is`(VFileProperty.SYMLINK)) {
            return emptyList()
        }
        if (vf.length > ManifestCompletionIndex.MAX_MANIFEST_BYTES) {
            return emptyList()
        }

        val modStamp = vf.modificationStamp
        val ts = vf.timeStamp
        val cached = cacheByProjectPath[manifestPath]
        if (cached != null && cached.modificationStamp == modStamp && cached.timeStamp == ts) {
            return cached.items
        }

        return try {
            val rawText = String(vf.contentsToByteArray(false), StandardCharsets.UTF_8)
            val parsed = ManifestCompletionIndex.parsePresentBindings(rawText)
            cacheByProjectPath[manifestPath] = CachedSnapshot(modStamp, ts, parsed)
            parsed
        } catch (ce: Exception) {
            if (ce is ControlFlowException) throw ce
            emptyList()
        }
    }
}
