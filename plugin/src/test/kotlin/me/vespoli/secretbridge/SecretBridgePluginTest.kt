package me.vespoli.secretbridge

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Assert.fail
import org.junit.Test
import java.io.BufferedReader
import java.io.InputStreamReader
import java.net.StandardProtocolFamily
import java.net.UnixDomainSocketAddress
import java.nio.ByteBuffer
import java.nio.channels.Channels
import java.nio.channels.ServerSocketChannel
import java.nio.charset.StandardCharsets
import java.nio.file.Files
import java.nio.file.Paths
import java.util.UUID
import java.util.concurrent.atomic.AtomicReference

class SecretBridgePluginTest {

    @Test
    fun jsonCodecZeroizesSecretCharArraysDuringConfigureSessionEncode() {
        val opChars = "sample-sa-credential-value".toCharArray()
        val ghChars = "sample-gh-credential-value".toCharArray()
        val creds = SessionCredentialsChars(
            opServiceAccountToken = opChars,
            githubToken = ghChars,
        )
        val req = HostCommand.Enclave(EnclaveRequest.ConfigureSession(creds))
        val encodedBytes = JsonCodec.encodeUtf8(req.toJson(), appendNewline = true)
        try {
            assertTrue("opChars must be zeroized after encodeUtf8", opChars.all { it == '\u0000' })
            assertTrue("ghChars must be zeroized after encodeUtf8", ghChars.all { it == '\u0000' })

            val text = String(encodedBytes, StandardCharsets.UTF_8)
            assertTrue(text.endsWith("\n"))
            val parsed = JsonCodec.parseObject(text.trim())
            assertEquals("enclave", parsed.reqStr("host_op"))
            val inner = parsed.reqObj("request")
            assertEquals("configure-session", inner.reqStr("action"))
            val parsedCreds = inner.reqObj("credentials")
            assertEquals("sample-sa-credential-value", parsedCreds.reqStr("op_service_account_token"))
            assertEquals("sample-gh-credential-value", parsedCreds.reqStr("github_token"))
            assertFalse(parsedCreds.entries.containsKey("aws_secret_access_key"))
        } finally {
            encodedBytes.fill(0)
        }
    }

    @Test
    fun manifestRejectsLegacyToolsBlockAndRoundTripsValidTargets() {
        val legacyWithTools = """
            {
              "version": 1,
              "project": "demo",
              "account": "acme.1password.com",
              "tools": { "run": "echo bad" },
              "environments": {
                "dev": { "vault": "demo-dev", "secrets": {} }
              }
            }
        """.trimIndent()

        try {
            Manifest.fromJson(JsonCodec.parseObject(legacyWithTools))
            fail("Expected ProtocolCodecException for legacy 'tools' field")
        } catch (expected: ProtocolCodecException) {
            assertTrue(expected.message!!.contains("tools"))
        }

        val validV2 = """
            {
              "version": 2,
              "project": "payments",
              "account": "acme.1password.com",
              "environments": {
                "prod": {
                  "vault": "payments-prod",
                  "secrets": {
                    "DB_PASSWORD": {
                      "ref": "op://payments-prod/rds-main/DB_PASSWORD",
                      "state": "present",
                      "github": true,
                      "aws": true
                    }
                  },
                  "github": {
                    "scope": "environment",
                    "host": "github.com",
                    "repository": "acme/payments",
                    "environment": "production"
                  },
                  "aws": {
                    "region": "us-east-1",
                    "account_id": "123456789012",
                    "prefix": "payments/prod/",
                    "recovery_days": 14
                  }
                }
              }
            }
        """.trimIndent()

        val manifest = Manifest.fromJson(JsonCodec.parseObject(validV2))
        assertEquals(2, manifest.version)
        assertEquals("payments", manifest.project)
        val roundTripped = Manifest.fromJson(manifest.toJson())
        assertEquals(manifest, roundTripped)
    }

    @Test
    fun signedPlanPreservesCanonicalPlanPayloadForApply() {
        val enclavePlannedJson = """
            {
              "kind": "planned",
              "plan": {
                "version": 1,
                "environment": "prod",
                "manifest_digest": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "source_revision_digest": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                "aws_identity": {
                  "account": "123456789012",
                  "arn": "arn:aws:iam::123456789012:role/deploy"
                },
                "issued_at_unix_secs": 1760000000,
                "operations": [
                  {
                    "target": "aws",
                    "name": "DB_PASSWORD",
                    "action": "create",
                    "resource": "payments/prod/DB_PASSWORD",
                    "destination": {
                      "region": "us-east-1",
                      "account_id": "123456789012",
                      "prefix": "payments/prod/",
                      "recovery_days": 30
                    },
                    "observed": {
                      "arn": null,
                      "versions": {},
                      "modified": null,
                      "deleted": null
                    }
                  }
                ]
              },
              "plan_mac": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
            }
        """.trimIndent()

        val result = EnclaveResult.fromJson(JsonCodec.parseObject(enclavePlannedJson)) as EnclaveResult.Planned
        assertEquals(1, result.signedPlan.operations.size)
        assertEquals("DB_PASSWORD", result.signedPlan.operations[0].name)

        val manifest = Manifest(
            version = 2,
            project = "payments",
            account = "acme.1password.com",
            environments = mapOf("prod" to EnvironmentConfig(vault = "payments-prod")),
        )
        val applyJson = EnclaveRequest.Apply(manifest, result.signedPlan).toJson()
        assertEquals("apply", applyJson.reqStr("action"))
        val signedObj = applyJson.reqObj("signed_plan")
        assertFalse("signed_plan must not leak internal tag 'kind'", signedObj.entries.containsKey("kind"))
        assertEquals(
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
            signedObj.reqStr("plan_mac"),
        )
        val innerPlan = signedObj.reqObj("plan")
        assertEquals("123456789012", innerPlan.reqObj("aws_identity").reqStr("account"))
        assertEquals(1760000000L, innerPlan.reqLong("issued_at_unix_secs"))
    }

    @Test
    fun vaultUiPolicyStrictlyGatesCreateVaultByServiceAccountCapability() {
        val unauthenticated = VaultUiPolicy.computeCreateVaultButtonState(null)
        assertFalse(unauthenticated.enabled)

        val deniedCaps = ServiceAccountCapabilities(
            authenticated = true,
            canCreateVaults = false,
            accessibleVaultIds = listOf("v1"),
            readOnlyVaultIds = emptyList(),
            notice = "Read/write items only",
        )
        val deniedState = VaultUiPolicy.computeCreateVaultButtonState(deniedCaps)
        assertFalse(deniedState.enabled)
        assertTrue(deniedState.tooltip.contains("can_create_vaults"))
        assertTrue(deniedState.tooltip.contains("Personal/Private"))

        val allowedCaps = deniedCaps.copy(canCreateVaults = true)
        val allowedState = VaultUiPolicy.computeCreateVaultButtonState(allowedCaps)
        assertTrue(allowedState.enabled)
    }

    @Test
    fun completionIndexFiltersFileTypesAndExcludesAbsentSecrets() {
        assertTrue(ManifestCompletionIndex.isEligibleFileName(".env"))
        assertTrue(ManifestCompletionIndex.isEligibleFileName(".env.staging"))
        assertTrue(ManifestCompletionIndex.isEligibleFileName("ci.yaml"))
        assertTrue(ManifestCompletionIndex.isEligibleFileName("secrets.tf"))
        assertTrue(ManifestCompletionIndex.isEligibleFileName("Service.kt"))
        assertFalse(ManifestCompletionIndex.isEligibleFileName("secretbridge.json"))
        assertFalse(ManifestCompletionIndex.isEligibleFileName("icon.png"))
        assertFalse(ManifestCompletionIndex.isEligibleFileName("README.md"))

        val manifestJson = """
            {
              "version": 2,
              "project": "svc",
              "account": "acme.1password.com",
              "environments": {
                "dev": {
                  "vault": "svc-dev",
                  "secrets": {
                    "ACTIVE_KEY": { "ref": "op://svc-dev/item/ACTIVE_KEY", "state": "present" },
                    "OLD_KEY": { "state": "absent" }
                  }
                }
              }
            }
        """.trimIndent()

        val items = ManifestCompletionIndex.parsePresentBindings(manifestJson)
        assertEquals(1, items.size)
        assertEquals("ACTIVE_KEY", items[0].secretName)
        assertEquals("op://svc-dev/item/ACTIVE_KEY", items[0].opRef)
    }

    @Test
    fun hostCliBuilderEnforcesSha256DigestsAndRejectsOptionInjection() {
        val badBin = BridgeSettings.StateData(sbHostBinaryPath = "--bad-flag")
        try {
            badBin.buildHostCliArgs("/path/h.sock", "/path/e.sock")
            fail("Expected IllegalArgumentException for flag-like binary path")
        } catch (_: IllegalArgumentException) {
        }

        val missingDigest = BridgeSettings.StateData(
            backendMode = HostBackendMode.KVM_MICROVM.wireValue,
            kernelPath = "/opt/sb/vmlinuz",
            initramfsPath = "/opt/sb/initramfs.cpio",
            kernelSha256 = "short",
            initramfsSha256 = "0".repeat(64),
        )
        try {
            missingDigest.buildHostCliArgs("/path/h.sock", "/path/e.sock")
            fail("Expected IllegalArgumentException for invalid SHA-256")
        } catch (_: IllegalArgumentException) {
        }

        val validKvm = missingDigest.copy(kernelSha256 = "a".repeat(64), initramfsSha256 = "b".repeat(64))
        val args = validKvm.buildHostCliArgs("/path/h.sock", "/path/e.sock")
        assertEquals("sb-host", args[0])
        assertTrue(args.contains("--kernel-sha256"))
        assertTrue(args.contains("a".repeat(64)))
    }

    @Test
    fun hostSocketTransportRoundTripsArmedCaptureOverUnixSocket() {
        val home = System.getProperty("user.home")
        assertNotNull(home)
        val dir = Paths.get(home, ".local", "run", "sb-junit-${UUID.randomUUID().toString().take(8)}")
        Files.createDirectories(dir)
        val sockPath = dir.resolve("h.sock")
        val expectedToken = "d".repeat(64)
        val serverCapturedLine = AtomicReference<String>()

        try {
            ServerSocketChannel.open(StandardProtocolFamily.UNIX).use { server ->
                server.bind(UnixDomainSocketAddress.of(sockPath))
                val serverThread = Thread {
                    server.accept().use { client ->
                        val reader = BufferedReader(
                            InputStreamReader(Channels.newInputStream(client), StandardCharsets.UTF_8),
                        )
                        serverCapturedLine.set(reader.readLine())
                        val reply = """
                            {"ok":true,"enclave":{"ok":true,"result":{"kind":"secret-stored","item_id":"it-1","title":"stripe","field_id":"f-1","ref":"op://dev/stripe/API_KEY","intercept_mode":"zero-pasteboard"}}}
                        """.trimIndent() + "\n"
                        client.write(ByteBuffer.wrap(reply.toByteArray(StandardCharsets.UTF_8)))
                    }
                }
                serverThread.start()

                val banner = "SB_HOST_READY socket=$sockPath token=$expectedToken"
                val (parsedPath, tokenChars) = HostSocketTransport.parseReadyBanner(banner)
                assertEquals(sockPath, parsedPath)

                HostSocketTransport(parsedPath, tokenChars).use { transport ->
                    tokenChars.fill('\u0000')
                    val resp = transport.execute(
                        HostCommand.ArmedCapture(
                            manifestPath = "/repo/secretbridge.json",
                            environment = "dev",
                            target = CaptureTarget.NewItem(title = "stripe", fieldName = "API_KEY"),
                        ),
                    )
                    val stored = resp.requireEnclaveResult() as EnclaveResult.SecretStored
                    assertEquals("op://dev/stripe/API_KEY", stored.receipt.ref)
                    assertEquals(CaptureInterceptMode.ZERO_PASTEBOARD, stored.receipt.interceptMode)
                }

                serverThread.join(5_000)
                val receivedJson = JsonCodec.parseObject(serverCapturedLine.get())
                assertEquals(expectedToken, receivedJson.reqStr("auth_token_hex"))
                assertEquals("armed-capture", receivedJson.reqObj("command").reqStr("host_op"))
            }
        } finally {
            Files.deleteIfExists(sockPath)
            Files.deleteIfExists(dir)
        }
    }

    @Test
    fun kotlinPluginEndToEndWithRealRustHostAndEnclaveOverNoiseIk() {
        val cwd = Paths.get("").toAbsolutePath().normalize()
        val repoRoot = if (cwd.fileName?.toString() == "plugin") cwd.parent else cwd
        val sbHostBin = repoRoot.resolve("target/debug/sb-host")
        val sbEnclaveBin = repoRoot.resolve("target/debug/sb-enclave")
        if (!Files.isExecutable(sbHostBin) || !Files.isExecutable(sbEnclaveBin)) {
            return
        }

        val home = System.getProperty("user.home")!!
        val runDir = Paths.get(home, ".local", "run", "sb-e2e-${UUID.randomUUID().toString().take(8)}")
        Files.createDirectories(runDir)
        val ideSock = runDir.resolve("h.sock")
        val enclaveSock = runDir.resolve("e.sock")
        val manifestFile = runDir.resolve("secretbridge.json")

        val proc = ProcessBuilder(
            sbHostBin.toString(),
            "--ide-socket",
            ideSock.toString(),
            "--enclave-bin",
            sbEnclaveBin.toString(),
            "--enclave-socket",
            enclaveSock.toString(),
            "--enclave-arg",
            "--in-memory-vault-test-token",
            "--enclave-arg",
            "junit-valid-sa-session",
        ).start()

        try {
            val stdout = BufferedReader(InputStreamReader(proc.inputStream, StandardCharsets.UTF_8))
            val readyLine = stdout.readLine()
            assertNotNull("Expected SB_HOST_READY line from sb-host", readyLine)
            val (boundSock, tokenChars) = HostSocketTransport.parseReadyBanner(readyLine!!)

            HostSocketTransport(boundSock, tokenChars).use { transport ->
                tokenChars.fill('\u0000')

                val cfgRes = transport.execute(
                    HostCommand.Enclave(
                        EnclaveRequest.ConfigureSession(
                            SessionCredentialsChars(
                                opServiceAccountToken = "junit-valid-sa-session".toCharArray(),
                            ),
                        ),
                    ),
                ).requireEnclaveResult() as EnclaveResult.SessionConfigured
                assertTrue(cfgRes.hasOpToken)

                val caps = (
                    transport.execute(HostCommand.Enclave(EnclaveRequest.Capabilities))
                        .requireEnclaveResult() as EnclaveResult.Capabilities
                    ).capabilities
                assertTrue(caps.authenticated)
                assertTrue(caps.canCreateVaults)

                val createdVault = (
                    transport.execute(HostCommand.Enclave(EnclaveRequest.VaultCreate("junit-dev")))
                        .requireEnclaveResult() as EnclaveResult.VaultCreated
                    ).vault
                assertEquals("junit-dev", createdVault.name)
                assertTrue(createdVault.writable)

                val initialManifest = Manifest(
                    version = 2,
                    project = "billing",
                    account = "acme.1password.com",
                    environments = mapOf("dev" to EnvironmentConfig(vault = createdVault.id)),
                )
                val savedManifest = transport.execute(
                    HostCommand.ManifestSave(manifestFile.toString(), initialManifest),
                ).requireManifest()

                val generated = (
                    transport.execute(
                        HostCommand.Enclave(
                            EnclaveRequest.GenerateSecret(
                                manifest = savedManifest,
                                environment = "dev",
                                target = CaptureTarget.NewItem(
                                    title = "stripe-webhook",
                                    fieldName = "SIGNING_SECRET",
                                ),
                                spec = GenerateSpec(length = 40, charset = SecretCharset.ALPHANUMERIC),
                            ),
                        ),
                    ).requireEnclaveResult() as EnclaveResult.SecretStored
                    ).receipt
                val expectedOpRef = "op://${createdVault.id}/${generated.itemId}/${generated.fieldId}"
                assertEquals(expectedOpRef, generated.ref)

                val boundManifest = transport.execute(
                    HostCommand.ManifestBind(
                        manifestPath = manifestFile.toString(),
                        environment = "dev",
                        name = "SIGNING_SECRET",
                        ref = generated.ref,
                    ),
                ).requireManifest()

                val renderedEnv = (
                    transport.execute(
                        HostCommand.Enclave(
                            EnclaveRequest.Template(
                                manifest = boundManifest,
                                environment = "dev",
                                kind = TemplateKind.ENV,
                            ),
                        ),
                    ).requireEnclaveResult() as EnclaveResult.TemplateRendered
                    ).content
                assertTrue(renderedEnv.contains("SIGNING_SECRET=\"$expectedOpRef\""))
            }
        } finally {
            proc.destroyForcibly()
            Files.deleteIfExists(manifestFile)
            Files.deleteIfExists(ideSock)
            Files.deleteIfExists(enclaveSock)
            Files.deleteIfExists(runDir)
        }
    }
}
