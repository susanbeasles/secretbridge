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
import java.nio.file.attribute.PosixFilePermissions
import java.util.UUID
import java.util.concurrent.atomic.AtomicReference

class SecretBridgePluginTest {

    @Test
    fun blake2s256MatchesRfc7693TestVectors() {
        val emptyDigest = BridgeSettings.encodeHexString(Blake2s256.hash(ByteArray(0)))
        assertEquals(
            "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9",
            emptyDigest,
        )

        val abcDigest = BridgeSettings.encodeHexString(
            Blake2s256.hash("abc".toByteArray(StandardCharsets.US_ASCII)),
        )
        assertEquals(
            "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982",
            abcDigest,
        )

        val multiBlock = ByteArray(128) { it.toByte() }
        val singlePass = BridgeSettings.encodeHexString(Blake2s256.hash(multiBlock))
        val splitPass = BridgeSettings.encodeHexString(
            Blake2s256.hashTwo(multiBlock.copyOfRange(0, 64), multiBlock.copyOfRange(64, 128)),
        )
        assertEquals(singlePass, splitPass)
    }

    @Test
    fun jsonCodecZeroizesSecretCharsHandlesSurrogatePairsRejectsSignedHexAndDeepNesting() {
        val sampleSa = buildString {
            append("sample-sa-")
            append("credential-\uD83D\uDD10-val")
        }
        val sampleGh = buildString {
            append("sample-gh-")
            append("credential-val")
        }
        val opChars = sampleSa.toCharArray()
        val ghChars = sampleGh.toCharArray()
        val largeSessSecret = "s".repeat(2_400)
        val sessChars = largeSessSecret.toCharArray()
        val creds = SessionCredentialsChars(
            opServiceAccountToken = opChars,
            githubToken = ghChars,
            awsSessionToken = sessChars,
            allowedGithubHosts = listOf("github.com"),
            allowedGithubOwners = listOf("acme"),
            allowedAwsAccountIds = listOf("123456789012"),
        )
        val req = EnclaveRequest.ConfigureSession(creds)
        val encodedBytes = JsonCodec.encodeUtf8(req.toJson(), appendNewline = true)
        try {
            assertTrue("Encoded payload must exceed initial 512-byte stream capacity", encodedBytes.size > 2_500)
            assertTrue("opChars must be zeroized after encodeUtf8", opChars.all { it == '\u0000' })
            assertTrue("ghChars must be zeroized after encodeUtf8", ghChars.all { it == '\u0000' })
            assertTrue("sessChars must be zeroized after encodeUtf8", sessChars.all { it == '\u0000' })

            val text = String(encodedBytes, StandardCharsets.UTF_8)
            assertTrue(text.endsWith("\n"))
            val parsed = JsonCodec.parseObject(text.trim())
            assertEquals("configure-session", parsed.reqStr("action"))
            val parsedCreds = parsed.reqObj("credentials")
            assertEquals(sampleSa, parsedCreds.reqStr("op_service_account_token"))
            assertEquals(sampleGh, parsedCreds.reqStr("github_token"))
            assertEquals(largeSessSecret, parsedCreds.reqStr("aws_session_token"))
            assertEquals(listOf("acme"), parsedCreds.strList("allowed_github_owners"))
            assertFalse(parsedCreds.entries.containsKey("aws_secret_access_key"))
        } finally {
            encodedBytes.fill(0)
        }

        // Surrogate-pair round-trip inside JsonStr (4-byte UTF-8 rather than CESU-8)
        val lockStr = "prefix-\uD83D\uDD10-suffix"
        val strEncoded = JsonCodec.encodeUtf8(JsonObj(mapOf("v" to JsonStr(lockStr))), appendNewline = false)
        assertEquals(lockStr, JsonCodec.parseObject(String(strEncoded, StandardCharsets.UTF_8)).reqStr("v"))

        // Reject signed \u+041 / \u-041 hex escape sequences
        for (badEscape in listOf("{\"k\":\"\\u+041\"}", "{\"k\":\"\\u-041\"}")) {
            try {
                JsonCodec.parseObject(badEscape)
                fail("Expected ProtocolCodecException for malformed unicode escape: $badEscape")
            } catch (_: ProtocolCodecException) {
            }
        }

        // Enforce MAX_DEPTH = 64 recursion ceiling
        val deepNested = "[".repeat(70) + "1" + "]".repeat(70)
        try {
            JsonCodec.parse(deepNested)
            fail("Expected ProtocolCodecException for deeply nested JSON")
        } catch (expected: ProtocolCodecException) {
            assertTrue(expected.message!!.contains("depth"))
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
                      "aws": true,
                      "allow_unmanaged_github_delete": true
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
        assertTrue(manifest.environments.getValue("prod").secrets.getValue("DB_PASSWORD").allowUnmanagedGithubDelete)
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
    fun hostCliBuilderAndReadyBannerParserHandleSpacesInSocketPathAndEnforceDigests() {
        val validClientPub = "f".repeat(64)
        val validPinnedEnclavePub = "c".repeat(64)

        val badBin = BridgeSettings.StateData(
            sbHostBinaryPath = "--bad-flag",
            pinnedEnclavePubkeyHex = validPinnedEnclavePub,
        )
        try {
            badBin.buildHostCliArgs("/path/h.sock", "/path/e.sock", validClientPub, 42)
            fail("Expected IllegalArgumentException for flag-like binary path")
        } catch (_: IllegalArgumentException) {
        }

        val missingDigest = BridgeSettings.StateData(
            backendMode = HostBackendMode.KVM_MICROVM.wireValue,
            kernelPath = "/opt/sb/vmlinuz",
            initramfsPath = "/opt/sb/initramfs.cpio",
            kernelSha256 = "short",
            initramfsSha256 = "0".repeat(64),
            pinnedEnclavePubkeyHex = validPinnedEnclavePub,
        )
        try {
            missingDigest.buildHostCliArgs("/path/h.sock", "/path/e.sock", validClientPub, 42)
            fail("Expected IllegalArgumentException for invalid SHA-256")
        } catch (_: IllegalArgumentException) {
        }

        // Unpinned or all-zero enclave pubkey must fail closed before launching sb-host
        for (badPin in listOf("", "0".repeat(64))) {
            val unpinnedKvm = missingDigest.copy(
                kernelSha256 = "a".repeat(64),
                initramfsSha256 = "b".repeat(64),
                pinnedEnclavePubkeyHex = badPin,
            )
            try {
                unpinnedKvm.buildHostCliArgs("/path/h.sock", "/path/e.sock", validClientPub, 42)
                fail("Expected IllegalArgumentException for unpinned/zero enclave pubkey: '$badPin'")
            } catch (_: IllegalArgumentException) {
            }
        }

        val validKvm = missingDigest.copy(
            kernelSha256 = "a".repeat(64),
            initramfsSha256 = "b".repeat(64),
            pinnedEnclavePubkeyHex = validPinnedEnclavePub,
        )
        val args = validKvm.buildHostCliArgs("/path/h.sock", "/path/e.sock", validClientPub, 77)
        assertEquals("sb-host", args[0])
        assertTrue(args.contains("--kernel-sha256"))
        assertTrue(args.contains("a".repeat(64)))
        assertTrue(args.contains("--authorized-client-pubkey-hex"))
        assertTrue(args.contains(validClientPub))
        assertTrue(args.contains("77"))

        // EXISTING_VSOCK must use configured guestCid unchanged even if effectiveGuestCid differs
        val existingVsock = BridgeSettings.StateData(
            backendMode = HostBackendMode.EXISTING_VSOCK.wireValue,
            guestCid = 42,
            vsockPort = 5190,
            enclavePubkeyHex = "e".repeat(64),
        )
        val existingArgs = existingVsock.buildHostCliArgs("/path/h.sock", "/path/e.sock", validClientPub, 999)
        val cidIdx = existingArgs.indexOf("--guest-cid")
        assertTrue(cidIdx >= 0)
        assertEquals("42", existingArgs[cidIdx + 1])
        assertFalse(existingArgs.contains("999"))

        val spacePath = "/Users/Anthony Vespoli/Library/Application Support/sb/h.sock"
        val banner = "SB_HOST_READY token=${"d".repeat(64)} enckey=${"e".repeat(64)} socket=$spacePath"
        val parsed = HostSocketTransport.parseReadyBanner(banner)
        assertEquals(Paths.get(spacePath), parsed.socketPath)
        assertEquals("d".repeat(64), String(parsed.authTokenChars))
        assertEquals("e".repeat(64), BridgeSettings.encodeHexString(parsed.enclavePubkey32))
        parsed.authTokenChars.fill('\u0000')
    }

    @Test
    fun hostCidLeaseAndSequentialCredentialExecutorEnforceIsolationAndFifoOrder() {
        val home = System.getProperty("user.home")!!
        val cidDir = Paths.get(home, ".local", "run", "sb-cid-junit-${UUID.randomUUID().toString().take(8)}")
        try {
            val lease1 = BridgeSettings.acquireHostCidLeaseInDir(42, cidDir)
            val lease2 = BridgeSettings.acquireHostCidLeaseInDir(42, cidDir)
            assertEquals(42, lease1.cid)
            assertEquals(43, lease2.cid)
            lease1.close()

            val reclaimed = BridgeSettings.acquireHostCidLeaseInDir(42, cidDir)
            assertEquals(42, reclaimed.cid)
            reclaimed.close()
            lease2.close()
        } finally {
            Files.deleteIfExists(cidDir.resolve("ide-cid-42.lock"))
            Files.deleteIfExists(cidDir.resolve("ide-cid-43.lock"))
            Files.deleteIfExists(cidDir)
        }

        val settings = BridgeSettings()
        val pubOnly = settings.loadOrCreateClientNoisePublicKeyOffEdt()
        assertEquals(32, pubOnly.size)
        assertFalse(pubOnly.all { it == 0.toByte() })
        val (privPair, pubPair) = settings.loadOrCreateClientNoiseKeypairOffEdt()
        try {
            assertTrue(NoiseIkSession.constantTimeEquals(pubOnly, pubPair))
        } finally {
            privPair.fill(0)
        }

        val observedOrder = ArrayList<Int>()
        val futures = (1..5).map { step ->
            settings.submitCredentialTransaction {
                Thread.sleep((6 - step) * 5L)
                synchronized(observedOrder) {
                    observedOrder.add(step)
                }
            }
        }
        futures.forEach { it.get() }
        assertEquals(listOf(1, 2, 3, 4, 5), observedOrder)
    }

    @Test
    fun hostSocketTransportRoundTripsCaptureAndSealOverUnixSocket() {
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
                            {"ok":true,"sealed_secret_b64":"c2VhbGVk","intercept_mode":"zero-pasteboard"}
                        """.trimIndent() + "\n"
                        client.write(ByteBuffer.wrap(reply.toByteArray(StandardCharsets.UTF_8)))
                    }
                }
                serverThread.start()

                val banner = "SB_HOST_READY token=$expectedToken enckey=${"1".repeat(64)} socket=$sockPath"
                val parsed = HostSocketTransport.parseReadyBanner(banner)
                assertEquals(sockPath, parsed.socketPath)

                HostSocketTransport(parsed.socketPath, parsed.authTokenChars).use { transport ->
                    parsed.authTokenChars.fill('\u0000')
                    val resp = transport.execute(
                        HostCommand.CaptureAndSeal(
                            pkCaptureB64 = "cGtfdGVzdA==",
                            ttlMs = 15_000L,
                        ),
                    )
                    val (sealedB64, mode) = resp.requireSealedCapture()
                    assertEquals("c2VhbGVk", sealedB64)
                    assertEquals(CaptureInterceptMode.ZERO_PASTEBOARD, mode)
                }

                serverThread.join(5_000)
                val receivedJson = JsonCodec.parseObject(serverCapturedLine.get())
                assertEquals(expectedToken, receivedJson.reqStr("auth_token_hex"))
                val cmdObj = receivedJson.reqObj("command")
                assertEquals("capture-and-seal", cmdObj.reqStr("host_op"))
                assertEquals("cGtfdGVzdA==", cmdObj.reqStr("pk_capture_b64"))
            }
        } finally {
            Files.deleteIfExists(sockPath)
            Files.deleteIfExists(dir)
        }
    }

    @Test
    fun kotlinPluginEndToEndWithRealRustHostAndEnclaveOverNoiseIkAndRekey() {
        val cwd = Paths.get("").toAbsolutePath().normalize()
        val repoRoot = if (cwd.fileName?.toString() == "plugin") cwd.parent else cwd
        val sbHostBin = repoRoot.resolve("target/debug/sb-host")
        val sbEnclaveBin = repoRoot.resolve("target/debug/sb-enclave")
        assertTrue(
            "Expected built Rust binaries at $sbHostBin and $sbEnclaveBin",
            Files.isExecutable(sbHostBin) && Files.isExecutable(sbEnclaveBin),
        )
        try {
            val execPerms = PosixFilePermissions.fromString("rwxr-xr-x")
            Files.setPosixFilePermissions(sbHostBin, execPerms)
            Files.setPosixFilePermissions(sbEnclaveBin, execPerms)
        } catch (_: UnsupportedOperationException) {
        }

        val home = System.getProperty("user.home")!!
        val runDir = Paths.get(home, ".local", "run", "sb-e2e-${UUID.randomUUID().toString().take(8)}")
        Files.createDirectories(runDir)
        try {
            Files.setPosixFilePermissions(runDir, PosixFilePermissions.fromString("rwx------"))
        } catch (_: UnsupportedOperationException) {
        }
        val ideSock = runDir.resolve("h.sock")
        val enclaveSock = runDir.resolve("e.sock")
        val enclaveKeyFile = runDir.resolve("enclave_noise.key")
        val enclavePubFile = runDir.resolve("enclave_noise.pub")
        val manifestFile = runDir.resolve("secretbridge.json")

        // Provision an independent enclave static identity out-of-band (never trusting SB_HOST_READY)
        val genExit = ProcessBuilder(
            sbEnclaveBin.toString(),
            "--generate-identity",
            enclaveKeyFile.toString(),
            enclavePubFile.toString(),
        ).start().waitFor()
        assertEquals("sb-enclave --generate-identity must exit 0", 0, genExit)
        val provisionedPubHex = Files.readString(enclavePubFile, StandardCharsets.UTF_8).trim()
        val provisionedPub32 = BridgeSettings.decodeHex32(provisionedPubHex)

        val (clientPriv, clientPub) = NoiseIkSession.generateStaticKeypair()
        val clientPubHex = BridgeSettings.encodeHexString(clientPub)
        val runtimeTestToken = buildString {
            append("junit-")
            append("valid-")
            append("sa-session")
        }

        val proc = ProcessBuilder(
            sbHostBin.toString(),
            "--ide-socket",
            ideSock.toString(),
            "--enclave-bin",
            sbEnclaveBin.toString(),
            "--enclave-socket",
            enclaveSock.toString(),
            "--enclave-key-file",
            enclaveKeyFile.toString(),
            "--authorized-client-pubkey-hex",
            clientPubHex,
            "--enclave-arg",
            "--in-memory-vault-test-token",
            "--enclave-arg",
            runtimeTestToken,
        ).start()

        try {
            val stdout = BufferedReader(InputStreamReader(proc.inputStream, StandardCharsets.UTF_8))
            val readyLine = stdout.readLine()
            if (readyLine == null) {
                val errText = proc.errorStream.bufferedReader(StandardCharsets.UTF_8).readText()
                fail("Expected SB_HOST_READY line from sb-host, stderr was: $errText")
            }
            val parsed = HostSocketTransport.parseReadyBanner(readyLine!!)
            assertTrue(
                "Enclave banner pubkey must match independently provisioned static pubkey",
                NoiseIkSession.constantTimeEquals(provisionedPub32, parsed.enclavePubkey32),
            )

            // Verify a mismatched pinned enclave public key fails closed BEFORE sending credentials
            val (_, wrongPinnedPub) = NoiseIkSession.generateStaticKeypair()
            try {
                HostSocketTransport(
                    socketPath = parsed.socketPath,
                    authTokenHex = parsed.authTokenChars,
                    clientPrivateKey32 = clientPriv,
                    expectedEnclavePubkey32 = wrongPinnedPub,
                ).use { mismatchedTransport ->
                    mismatchedTransport.executeEnclave(EnclaveRequest.Capabilities)
                    fail("Expected mismatched pinned enclave pubkey to fail closed before Noise_IK handshake")
                }
            } catch (expected: EnclaveBridgeException) {
                assertEquals("unauthorized", expected.code)
            }

            // Verify an unauthorized Kotlin Noise static keypair is rejected by sb-enclave
            val (roguePriv, _) = NoiseIkSession.generateStaticKeypair()
            try {
                HostSocketTransport(
                    socketPath = parsed.socketPath,
                    authTokenHex = parsed.authTokenChars,
                    clientPrivateKey32 = roguePriv,
                    expectedEnclavePubkey32 = provisionedPub32,
                ).use { rogueTransport ->
                    rogueTransport.executeEnclave(EnclaveRequest.Capabilities)
                    fail("Expected unauthorized Noise_IK client keypair to be rejected by sb-enclave")
                }
            } catch (_: EnclaveBridgeException) {
            } finally {
                roguePriv.fill(0)
            }

            HostSocketTransport(
                socketPath = parsed.socketPath,
                authTokenHex = parsed.authTokenChars,
                clientPrivateKey32 = clientPriv,
                expectedEnclavePubkey32 = provisionedPub32,
            ).use { transport ->
                parsed.authTokenChars.fill('\u0000')

                val cfgRes = transport.executeEnclave(
                    EnclaveRequest.ConfigureSession(
                        SessionCredentialsChars(
                            opServiceAccountToken = runtimeTestToken.toCharArray(),
                            allowedGithubHosts = listOf("github.com"),
                            allowedGithubOwners = listOf("acme"),
                        ),
                    ),
                ) as EnclaveResult.SessionConfigured
                assertTrue(cfgRes.hasOpToken)

                val caps = (transport.executeEnclave(EnclaveRequest.Capabilities) as EnclaveResult.Capabilities)
                    .capabilities
                assertTrue(caps.authenticated)
                assertTrue(caps.canCreateVaults)

                val createdVault = (
                    transport.executeEnclave(EnclaveRequest.VaultCreate("junit-dev")) as EnclaveResult.VaultCreated
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

                val captureStart = transport.executeEnclave(
                    EnclaveRequest.BeginCapture(
                        manifest = savedManifest,
                        environment = "dev",
                        target = CaptureTarget.NewItem(title = "api-token", fieldName = "TOKEN"),
                    ),
                ) as EnclaveResult.CaptureStarted
                assertTrue(captureStart.captureId.isNotBlank())
                assertTrue(captureStart.pkCaptureB64.isNotBlank())

                val generated = (
                    transport.executeEnclave(
                        EnclaveRequest.GenerateSecret(
                            manifest = savedManifest,
                            environment = "dev",
                            target = CaptureTarget.NewItem(
                                title = "stripe-webhook",
                                fieldName = "SIGNING_SECRET",
                            ),
                            spec = GenerateSpec(length = 40, charset = SecretCharset.ALPHANUMERIC),
                        ),
                    ) as EnclaveResult.SecretStored
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
                    transport.executeEnclave(
                        EnclaveRequest.Template(
                            manifest = boundManifest,
                            environment = "dev",
                            kind = TemplateKind.ENV,
                        ),
                    ) as EnclaveResult.TemplateRendered
                    ).content
                assertTrue(renderedEnv.contains("SIGNING_SECRET=\"$expectedOpRef\""))

                // Exercise >1,024 frames in a single Noise_IK session to prove synchronized
                // Kotlin <-> Rust `snow` ChaChaPoly transport cipherstate rekeying (`H1`)!
                val rekeyBatch = List(1_030) { EnclaveRequest.Capabilities }
                val batchResults = transport.executeEnclaveBatch(rekeyBatch)
                assertEquals(1_030, batchResults.size)
                assertTrue((batchResults.last() as EnclaveResult.Capabilities).capabilities.authenticated)
            }
        } finally {
            provisionedPub32.fill(0)
            clientPriv.fill(0)
            proc.destroyForcibly()
            Files.deleteIfExists(manifestFile)
            Files.deleteIfExists(enclaveKeyFile)
            Files.deleteIfExists(enclavePubFile)
            Files.deleteIfExists(ideSock)
            Files.deleteIfExists(enclaveSock)
            Files.deleteIfExists(runDir)
        }
    }
}
