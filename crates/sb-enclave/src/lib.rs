pub mod aws;
pub mod error;
pub mod github;
pub mod mem_secret;
pub mod service;
pub mod templates;
pub mod vault;
pub mod vsock;

#[cfg(test)]
mod tests {
    use crate::aws::{InMemoryAwsClient, TAG_ENVIRONMENT, TAG_PROJECT};
    use crate::github::{InMemoryGitHubClient, is_public_unicast_ip};
    use crate::mem_secret::MemSecret;
    use crate::service::EnclaveService;
    use crate::templates::escape_hcl_string;
    use crate::vault::{
        ForeignBytes, InMemoryVaultProvider, RustBuffer, RustCallStatus, UniffiCoreVaultProvider,
        UniffiSymbolTable, VaultProvider,
    };
    use crate::vsock::serve_noise_connection;
    use sb_proto::crypto::{NoiseSession, generate_noise_keypair, seal_base64};
    use sb_proto::error::ErrorCode;
    use sb_proto::plan::PlanAction;
    use sb_proto::rpc::{
        CaptureInterceptMode, CaptureTarget, EnclaveRequest, EnclaveResponse, EnclaveResult,
        GenerateSpec, SecretCharset, SessionCredentialsInput, TemplateKind,
    };
    use sb_proto::types::{Manifest, OpRef, SecretName, SecretState, Slug};
    use std::collections::BTreeMap;
    use std::net::IpAddr;
    use std::sync::{Arc, Mutex};
    use std::thread;

    fn dummy_op_token() -> String {
        format!("{}_{}_{}", "dummy", "op_sa", 101)
    }

    fn dummy_gh_token() -> String {
        format!("{}_{}_{}", "dummy", "gh_tok", 202)
    }

    fn dummy_aws_ak() -> String {
        format!("{}{}", "TEST", "0000000000000001")
    }

    fn dummy_aws_sk() -> String {
        format!("{}/{}/{}", "unit_test_only", "not_a_key", 303)
    }

    fn sample_manifest() -> Manifest {
        Manifest::from_json_str(
            r#"{
              "version": 2,
              "project": "secretbridge",
              "account": "vespoli.1password.com",
              "environments": {
                "dev": {
                  "vault": "vault-dev-01",
                  "secrets": {
                    "DATABASE_URL": {
                      "ref": "op://vault-dev-01/item-db/url",
                      "state": "present",
                      "github": true,
                      "aws": true
                    },
                    "API_KEY": {
                      "ref": "op://vault-dev-01/item-api/token",
                      "state": "present",
                      "github": true,
                      "aws": true
                    }
                  },
                  "github": {
                    "host": "github.com",
                    "scope": "repository",
                    "repository": "susanbeasles/secretbridge"
                  },
                  "aws": {
                    "region": "us-west-2",
                    "account_id": "123456789012",
                    "prefix": "secretbridge/dev/",
                    "recovery_days": 7
                  }
                },
                "staging": {
                  "vault": "vault-stg-01",
                  "secrets": {}
                }
              }
            }"#,
        )
        .expect("valid manifest")
    }

    fn build_fixture(
        can_create_vaults: bool,
    ) -> (
        Arc<EnclaveService>,
        Arc<InMemoryVaultProvider>,
        Arc<InMemoryAwsClient>,
        Arc<InMemoryGitHubClient>,
    ) {
        let op_tok = dummy_op_token();
        let vault = Arc::new(InMemoryVaultProvider::new(&op_tok, can_create_vaults));
        vault.seed_vault("vault-dev-01", "Dev Vault", true, true);
        vault.seed_vault("vault-stg-01", "Staging Vault", true, false);
        vault.seed_item(
            "vault-dev-01",
            "item-db",
            "Database URL",
            "API_CREDENTIAL",
            vec![("url", "url", None, "postgres://app:supersecret@db:5432/app")],
        );
        vault.seed_item(
            "vault-dev-01",
            "item-api",
            "API Key",
            "PASSWORD",
            vec![("token", "token", None, "sk_live_987654321")],
        );
        // Seed a non-safe category item (LOGIN) to verify S5 enforcement
        vault.seed_item(
            "vault-dev-01",
            "item-login-unsafe",
            "Human Browser Login",
            "LOGIN",
            vec![("password", "password", None, "human-pass")],
        );

        let aws = Arc::new(InMemoryAwsClient::new(
            "123456789012",
            "arn:aws:iam::123456789012:role/deploy",
        ));
        let gh = Arc::new(InMemoryGitHubClient::new("anthonyvespoli"));
        let svc = Arc::new(EnclaveService::new(
            Arc::clone(&vault) as _,
            Arc::clone(&aws) as _,
            Arc::clone(&gh) as _,
        ));

        let cfg_resp = svc.handle(EnclaveRequest::ConfigureSession {
            credentials: SessionCredentialsInput {
                op_service_account_token: Some(op_tok),
                github_token: Some(dummy_gh_token()),
                aws_access_key_id: Some(dummy_aws_ak()),
                aws_secret_access_key: Some(dummy_aws_sk()),
                aws_session_token: None,
                allowed_github_hosts: vec!["github.com".into()],
                allowed_github_owners: vec!["susanbeasles".into()],
                allowed_aws_account_ids: vec!["123456789012".into()],
            },
        });
        assert!(cfg_resp.ok);
        (svc, vault, aws, gh)
    }

    #[test]
    fn gates_vault_creation_and_blocks_personal_private_vaults() {
        let (svc_no_create, _, _, _) = build_fixture(false);
        let cap_resp = svc_no_create.handle(EnclaveRequest::Capabilities);
        assert!(cap_resp.ok);
        let Some(EnclaveResult::Capabilities(caps)) = cap_resp.result else {
            panic!("expected capabilities");
        };
        assert!(!caps.can_create_vaults);

        let denied = svc_no_create.handle(EnclaveRequest::VaultCreate {
            name: "New App Vault".into(),
        });
        assert!(!denied.ok);
        assert_eq!(denied.error.unwrap().code, ErrorCode::CapabilityDenied);

        let (svc_can_create, _, _, _) = build_fixture(true);
        for forbidden in ["Personal", "Private", "Employee"] {
            let rej = svc_can_create.handle(EnclaveRequest::VaultCreate {
                name: forbidden.into(),
            });
            assert!(!rej.ok);
            assert_eq!(rej.error.unwrap().code, ErrorCode::VaultRestriction);
        }

        let created = svc_can_create.handle(EnclaveRequest::VaultCreate {
            name: "Prod App Vault".into(),
        });
        assert!(created.ok);
    }

    #[test]
    fn enforces_safe_categories_on_edit_archive_and_move_closing_s5() {
        let (svc, _, _, _) = build_fixture(true);
        let manifest = sample_manifest();
        let dev: Slug = "dev".parse().unwrap();
        let stg: Slug = "staging".parse().unwrap();

        let archive_unsafe = svc.handle(EnclaveRequest::Archive {
            manifest: manifest.clone(),
            environment: dev.clone(),
            item: "item-login-unsafe".into(),
        });
        assert!(!archive_unsafe.ok);
        assert_eq!(
            archive_unsafe.error.unwrap().code,
            ErrorCode::CapabilityDenied
        );

        let move_unsafe = svc.handle(EnclaveRequest::Move {
            manifest: manifest.clone(),
            environment: dev.clone(),
            item: "item-login-unsafe".into(),
            destination: stg,
        });
        assert!(!move_unsafe.ok);
        assert_eq!(move_unsafe.error.unwrap().code, ErrorCode::CapabilityDenied);

        let edit_unsafe = svc.handle(EnclaveRequest::EditMetadata {
            manifest,
            environment: dev,
            item: "item-login-unsafe".into(),
            title: Some("Renamed".into()),
            tags: None,
            remove_field_id: None,
        });
        assert!(!edit_unsafe.ok);
        assert_eq!(edit_unsafe.error.unwrap().code, ErrorCode::CapabilityDenied);
    }

    #[test]
    fn csprng_generate_and_armed_copy_sealed_capture_never_expose_plaintext_in_responses() {
        let (svc, _, aws, _) = build_fixture(true);
        let mut manifest = sample_manifest();
        let dev: Slug = "dev".parse().unwrap();

        // 1. In-VM CSPRNG generation
        let gen_resp = svc.handle(EnclaveRequest::GenerateSecret {
            manifest: manifest.clone(),
            environment: dev.clone(),
            target: CaptureTarget::NewItem {
                title: "Generated JWT Key".into(),
                field_name: "JWT_SIGNING_KEY".parse().unwrap(),
                tags: vec!["backend".into()],
            },
            spec: GenerateSpec {
                length: 48,
                charset: SecretCharset::AlphanumericSymbols,
            },
        });
        assert!(gen_resp.ok);
        let gen_json = serde_json::to_string(&gen_resp).unwrap();
        let Some(EnclaveResult::SecretStored(gen_receipt)) = gen_resp.result else {
            panic!("expected SecretStored");
        };
        assert!(gen_receipt.r#ref.as_str().starts_with("op://vault-dev-01/"));
        assert!(!gen_json.contains("supersecret"));

        // 2. 15-second Armed Copy Hijack X25519 sealed-box capture + replay prevention
        let begin_resp = svc.handle(EnclaveRequest::BeginCapture {
            manifest: manifest.clone(),
            environment: dev.clone(),
            target: CaptureTarget::NewItem {
                title: "Stripe Webhook".into(),
                field_name: "STRIPE_WEBHOOK_SECRET".parse().unwrap(),
                tags: vec![],
            },
        });
        assert!(begin_resp.ok);
        let Some(EnclaveResult::CaptureStarted(challenge)) = begin_resp.result else {
            panic!("expected CaptureStarted");
        };
        assert_eq!(challenge.expires_in_ms, 15_000);

        let raw_captured = b"whsec_ultra_sensitive_never_touch_jvm_999";
        let sealed_b64 = seal_base64(&challenge.pk_capture_b64, raw_captured).unwrap();

        let complete_resp = svc.handle(EnclaveRequest::CompleteCapture {
            capture_id: challenge.capture_id.clone(),
            sealed_secret_b64: sealed_b64.clone(),
            mode: CaptureInterceptMode::ZeroPasteboard,
        });
        assert!(complete_resp.ok);
        let resp_serialized = serde_json::to_string(&complete_resp).unwrap();
        assert!(!resp_serialized.contains("whsec_ultra_sensitive"));

        let Some(EnclaveResult::SecretStored(cap_receipt)) = complete_resp.result else {
            panic!("expected SecretStored");
        };
        assert_eq!(
            cap_receipt.intercept_mode,
            Some(CaptureInterceptMode::ZeroPasteboard)
        );

        // Replay of the same capture_id must be rejected immediately (single-use challenge)
        let replay_resp = svc.handle(EnclaveRequest::CompleteCapture {
            capture_id: challenge.capture_id,
            sealed_secret_b64: sealed_b64,
            mode: CaptureInterceptMode::ZeroPasteboard,
        });
        assert!(!replay_resp.ok);
        assert_eq!(replay_resp.error.unwrap().code, ErrorCode::CaptureExpired);

        // Bind captured secret and sync to AWS inside enclave, verifying exact plaintext arrived in AWS
        manifest
            .bind_secret(
                &dev,
                "STRIPE_WEBHOOK_SECRET".parse().unwrap(),
                cap_receipt.r#ref,
                None,
                Some(false),
                Some(true),
            )
            .unwrap();
        let plan_resp = svc.handle(EnclaveRequest::Plan {
            manifest: manifest.clone(),
            environment: dev,
        });
        let Some(EnclaveResult::Planned(signed_plan)) = plan_resp.result else {
            panic!("expected Planned");
        };
        let apply_resp = svc.handle(EnclaveRequest::Apply {
            manifest,
            signed_plan,
        });
        assert!(apply_resp.ok);
        assert!(aws.stored_value_equals("secretbridge/dev/STRIPE_WEBHOOK_SECRET", raw_captured));
    }

    #[test]
    fn plan_apply_verifies_hmac_ownership_freshness_replay_and_reports_partial_failures() {
        let (svc, _, aws, gh) = build_fixture(true);
        svc.set_clock_override_for_test(Some(10_000));
        let mut manifest = sample_manifest();
        let dev: Slug = "dev".parse().unwrap();

        // Seed an unowned AWS secret -> plan must refuse with OwnershipConflict until adopt-aws
        aws.seed_existing(
            "secretbridge/dev/DATABASE_URL",
            "old-unowned-val",
            BTreeMap::new(),
            None,
        );
        let conflict_plan = svc.handle(EnclaveRequest::Plan {
            manifest: manifest.clone(),
            environment: dev.clone(),
        });
        assert!(!conflict_plan.ok);
        assert_eq!(
            conflict_plan.error.unwrap().code,
            ErrorCode::OwnershipConflict
        );

        // AdoptAws without confirm_unmanaged on untagged AWS secret must be refused (`H3`)
        let adopt_unconfirmed = svc.handle(EnclaveRequest::AdoptAws {
            manifest: manifest.clone(),
            environment: dev.clone(),
            name: "DATABASE_URL".parse::<SecretName>().unwrap(),
            confirm_unmanaged: false,
        });
        assert!(!adopt_unconfirmed.ok);
        assert_eq!(
            adopt_unconfirmed.error.unwrap().code,
            ErrorCode::OwnershipConflict
        );

        // Explicitly adopt AWS secret with operator confirmation (`confirm_unmanaged: true`)
        let adopt_resp = svc.handle(EnclaveRequest::AdoptAws {
            manifest: manifest.clone(),
            environment: dev.clone(),
            name: "DATABASE_URL".parse::<SecretName>().unwrap(),
            confirm_unmanaged: true,
        });
        assert!(adopt_resp.ok);

        // Plan succeeds now and NEVER contains `old-unowned-val` or any 1Password plaintext (closes S8)
        let plan_resp = svc.handle(EnclaveRequest::Plan {
            manifest: manifest.clone(),
            environment: dev.clone(),
        });
        assert!(plan_resp.ok);
        let plan_wire = serde_json::to_string(&plan_resp).unwrap();
        assert!(!plan_wire.contains("old-unowned-val"));
        assert!(!plan_wire.contains("supersecret"));
        let Some(EnclaveResult::Planned(signed_plan)) = plan_resp.result else {
            panic!("expected Planned");
        };

        // Tamper with plan_mac -> rejected (closes S4)
        let mut forged = signed_plan.clone();
        forged.plan_mac = "00".repeat(32);
        let forged_apply = svc.handle(EnclaveRequest::Apply {
            manifest: manifest.clone(),
            signed_plan: forged,
        });
        assert!(!forged_apply.ok);
        assert_eq!(forged_apply.error.unwrap().code, ErrorCode::StalePlan);

        // Mutate manifest after plan -> rejected as StalePlan WITHOUT burning signed_plan
        let mut mutated_manifest = manifest.clone();
        mutated_manifest
            .environments
            .get_mut(&dev)
            .unwrap()
            .secrets
            .get_mut(&"API_KEY".parse::<SecretName>().unwrap())
            .unwrap()
            .state = SecretState::Absent;
        let stale_apply = svc.handle(EnclaveRequest::Apply {
            manifest: mutated_manifest,
            signed_plan: signed_plan.clone(),
        });
        assert!(!stale_apply.ok);
        assert_eq!(stale_apply.error.unwrap().code, ErrorCode::StalePlan);

        // Simulate partial apply failure on `DATABASE_URL`
        aws.set_fail_on_secret(Some("secretbridge/dev/DATABASE_URL".into()));
        let partial_resp = svc.handle(EnclaveRequest::Apply {
            manifest: manifest.clone(),
            signed_plan: signed_plan.clone(),
        });
        assert!(partial_resp.ok);
        let Some(EnclaveResult::Applied(report)) = partial_resp.result else {
            panic!("expected ApplyReport");
        };
        assert!(!report.complete);
        assert!(report.results.iter().any(|r| r.succeeded));
        assert!(report.results.iter().any(|r| !r.succeeded));

        // Replaying `signed_plan` after execution started must fail closed (`H3` single-use consumption)
        let replay_apply = svc.handle(EnclaveRequest::Apply {
            manifest: manifest.clone(),
            signed_plan,
        });
        assert!(!replay_apply.ok);
        assert_eq!(replay_apply.error.unwrap().code, ErrorCode::StalePlan);

        // Clear failure, re-plan, and complete apply cleanly
        aws.set_fail_on_secret(None);
        let fresh_plan_resp = svc.handle(EnclaveRequest::Plan {
            manifest: manifest.clone(),
            environment: dev.clone(),
        });
        let Some(EnclaveResult::Planned(fresh_plan)) = fresh_plan_resp.result else {
            panic!("expected Planned");
        };
        let ok_apply = svc.handle(EnclaveRequest::Apply {
            manifest: manifest.clone(),
            signed_plan: fresh_plan,
        });
        let Some(EnclaveResult::Applied(full_report)) = ok_apply.result else {
            panic!("expected ApplyReport");
        };
        assert!(full_report.complete);
        assert!(full_report.pending.is_empty());

        // Verify both GitHub sealed box and AWS Secrets Manager received exact 1Password values
        let gh_target = manifest.environments[&dev].github.as_ref().unwrap().clone();
        let gh_db = gh
            .decrypt_stored_secret(&gh_target, "DATABASE_URL")
            .unwrap();
        assert_eq!(&gh_db[..], b"postgres://app:supersecret@db:5432/app");
        assert!(aws.stored_value_equals(
            "secretbridge/dev/DATABASE_URL",
            b"postgres://app:supersecret@db:5432/app"
        ));
        assert!(aws.stored_value_equals("secretbridge/dev/API_KEY", b"sk_live_987654321"));

        // Verify Delete action when a SecretBridge-managed secret transitions to Absent
        manifest.environments.get_mut(&dev).unwrap().secrets.insert(
            "API_KEY".parse().unwrap(),
            sb_proto::types::SecretSpec {
                r#ref: None::<OpRef>,
                state: SecretState::Absent,
                group: None,
                github: true,
                aws: true,
                allow_unmanaged_github_delete: false,
            },
        );
        let del_plan_resp = svc.handle(EnclaveRequest::Plan {
            manifest: manifest.clone(),
            environment: dev.clone(),
        });
        let Some(EnclaveResult::Planned(del_plan)) = del_plan_resp.result else {
            panic!("expected delete plan");
        };
        assert!(
            del_plan
                .plan
                .operations
                .iter()
                .any(|op| op.action() == PlanAction::Delete)
        );
        let del_apply = svc.handle(EnclaveRequest::Apply {
            manifest: manifest.clone(),
            signed_plan: del_plan,
        });
        assert!(del_apply.ok);

        // Verify pre-existing UNMANAGED GitHub secret deletion is refused unless allow_unmanaged_github_delete=true (`H3`)
        let unmanaged_name: SecretName = "LEGACY_CI_TOKEN".parse().unwrap();
        gh.seed_unmanaged_secret(&gh_target, &unmanaged_name, b"preexisting")
            .unwrap();
        manifest.environments.get_mut(&dev).unwrap().secrets.insert(
            unmanaged_name.clone(),
            sb_proto::types::SecretSpec {
                r#ref: None,
                state: SecretState::Absent,
                group: None,
                github: true,
                aws: false,
                allow_unmanaged_github_delete: false,
            },
        );
        let refused_gh_del = svc.handle(EnclaveRequest::Plan {
            manifest: manifest.clone(),
            environment: dev.clone(),
        });
        assert!(!refused_gh_del.ok);
        assert_eq!(
            refused_gh_del.error.unwrap().code,
            ErrorCode::OwnershipConflict
        );

        manifest
            .environments
            .get_mut(&dev)
            .unwrap()
            .secrets
            .get_mut(&unmanaged_name)
            .unwrap()
            .allow_unmanaged_github_delete = true;
        let allowed_gh_del = svc.handle(EnclaveRequest::Plan {
            manifest,
            environment: dev,
        });
        assert!(allowed_gh_del.ok);
        let _ = (TAG_PROJECT, TAG_ENVIRONMENT);
    }

    #[test]
    fn enforces_ssrf_ip_filter_host_binding_and_atomic_session_replacement_closing_c1_c2_h4() {
        // 1. PublicIpOnlyResolver filter (`C1`, `H4`)
        for blocked in [
            "127.0.0.1",
            "0.0.0.0",
            "10.0.2.2",        // QEMU SLIRP gateway
            "10.0.2.3",        // QEMU SLIRP DNS
            "172.16.0.1",      // RFC1918
            "192.168.1.1",     // RFC1918
            "169.254.169.254", // Cloud IMDS
            "100.64.0.1",      // CGNAT
            "::1",
            "fe80::1",
            "fc00::1",
            "::ffff:10.0.2.2", // IPv4-mapped SLIRP gateway
            "::ffff:127.0.0.1",
        ] {
            let ip: IpAddr = blocked.parse().unwrap();
            assert!(!is_public_unicast_ip(ip), "{blocked} must be blocked");
        }
        for public_ip in ["1.1.1.1", "140.82.112.4", "2606:4700:4700::1111"] {
            let ip: IpAddr = public_ip.parse().unwrap();
            assert!(is_public_unicast_ip(ip), "{public_ip} must be allowed");
        }

        // 2. Untrusted manifest pointing at `evil.example.com` or unauthorized owner/account (`C1`, `C2`)
        let (svc, _, _, _) = build_fixture(true);
        let dev: Slug = "dev".parse().unwrap();
        let mut evil_host_manifest = sample_manifest();
        evil_host_manifest
            .environments
            .get_mut(&dev)
            .unwrap()
            .github
            .as_mut()
            .unwrap()
            .host = "evil.example.com".parse().unwrap();

        let evil_plan = svc.handle(EnclaveRequest::Plan {
            manifest: evil_host_manifest.clone(),
            environment: dev.clone(),
        });
        assert!(!evil_plan.ok);
        assert_eq!(evil_plan.error.unwrap().code, ErrorCode::Unauthorized);

        // Doctor must report github-target:dev error without sending token to `evil.example.com`
        let doc_resp = svc.handle(EnclaveRequest::Doctor {
            manifest: Some(evil_host_manifest),
        });
        assert!(doc_resp.ok);
        let Some(EnclaveResult::Doctor { entries }) = doc_resp.result else {
            panic!("expected Doctor");
        };
        assert!(
            entries
                .iter()
                .any(|e| e.subsystem == "github-target:dev" && e.status == "error")
        );

        // 3. Atomic ConfigureSession wipes omitted tokens and invalidates prior SignedPlans (`C2`)
        let manifest = sample_manifest();
        let plan_before = svc.handle(EnclaveRequest::Plan {
            manifest: manifest.clone(),
            environment: dev,
        });
        let Some(EnclaveResult::Planned(old_plan)) = plan_before.result else {
            panic!("expected plan");
        };

        // Reconfigure session omitting `op_service_account_token` -> must atomically wipe it!
        let wipe_resp = svc.handle(EnclaveRequest::ConfigureSession {
            credentials: SessionCredentialsInput::default(),
        });
        assert!(wipe_resp.ok);
        let vaults_after_wipe = svc.handle(EnclaveRequest::Vaults);
        assert!(!vaults_after_wipe.ok);
        assert_eq!(
            vaults_after_wipe.error.unwrap().code,
            ErrorCode::Unauthorized
        );

        // Even after restoring identical credentials, `old_plan` must be rejected because `PlanSigner` rotated its HMAC key!
        let _ = svc.handle(EnclaveRequest::ConfigureSession {
            credentials: SessionCredentialsInput {
                op_service_account_token: Some(dummy_op_token()),
                github_token: Some(dummy_gh_token()),
                aws_access_key_id: Some(dummy_aws_ak()),
                aws_secret_access_key: Some(dummy_aws_sk()),
                aws_session_token: None,
                allowed_github_hosts: vec!["github.com".into()],
                allowed_github_owners: vec!["susanbeasles".into()],
                allowed_aws_account_ids: vec!["123456789012".into()],
            },
        });
        let old_apply = svc.handle(EnclaveRequest::Apply {
            manifest,
            signed_plan: old_plan,
        });
        assert!(!old_apply.ok);
        assert_eq!(old_apply.error.unwrap().code, ErrorCode::StalePlan);
    }

    #[test]
    fn uniffi_rustbuffer_abi_preserves_allocations_and_splices_secrets_without_heap_strings_closing_c3()
     {
        static ALLOC_LEDGER: Mutex<BTreeMap<usize, (u64, u64)>> = Mutex::new(BTreeMap::new());
        static MOCK_STORE: Mutex<Option<String>> = Mutex::new(None);

        unsafe extern "C" fn test_rb_from_bytes(
            bytes: ForeignBytes,
            status: *mut RustCallStatus,
        ) -> RustBuffer {
            unsafe {
                (*status).code = 0;
            }
            let len = bytes.len.max(0) as usize;
            // Deliberately allocate extra capacity (`len + 37`) to prove `zeroize_and_free_rustbuffer`
            // never clobbers `capacity` or `len` before calling `rustbuffer_free` (`C3`).
            let mut vec = Vec::<u8>::with_capacity(len + 37);
            if len > 0 && !bytes.data.is_null() {
                let slice = unsafe { std::slice::from_raw_parts(bytes.data, len) };
                vec.extend_from_slice(slice);
            }
            let cap = vec.capacity() as u64;
            let actual_len = vec.len() as u64;
            let ptr = vec.as_mut_ptr();
            std::mem::forget(vec);
            ALLOC_LEDGER
                .lock()
                .unwrap()
                .insert(ptr as usize, (cap, actual_len));
            RustBuffer {
                capacity: cap,
                len: actual_len,
                data: ptr,
            }
        }

        unsafe extern "C" fn test_rb_free(buf: RustBuffer, status: *mut RustCallStatus) {
            unsafe {
                (*status).code = 0;
            }
            if buf.data.is_null() {
                return;
            }
            let (expected_cap, expected_len) = ALLOC_LEDGER
                .lock()
                .unwrap()
                .remove(&(buf.data as usize))
                .expect("double-free or unknown RustBuffer pointer");
            assert_eq!(buf.capacity, expected_cap, "RustBuffer capacity corrupted");
            assert_eq!(buf.len, expected_len, "RustBuffer len corrupted");
            unsafe {
                let _ = Vec::from_raw_parts(buf.data, buf.len as usize, buf.capacity as usize);
            }
        }

        fn make_ret_buf(json: &str) -> RustBuffer {
            let mut status = RustCallStatus::default();
            let fb = ForeignBytes {
                len: json.len() as i32,
                data: json.as_ptr(),
            };
            unsafe { test_rb_from_bytes(fb, &raw mut status) }
        }

        unsafe extern "C" fn test_init_client(
            arg: RustBuffer,
            status: *mut RustCallStatus,
        ) -> RustBuffer {
            let slice = unsafe { std::slice::from_raw_parts(arg.data, arg.len as usize) };
            let text = std::str::from_utf8(slice).unwrap();
            assert!(text.contains("\"serviceAccountToken\":"));
            // UniFFI callee consumes `arg` by value (`C3`).
            let mut free_st = RustCallStatus::default();
            unsafe {
                test_rb_free(arg, &raw mut free_st);
                (*status).code = 0;
            }
            make_ret_buf("77")
        }

        unsafe extern "C" fn test_release_client(arg: RustBuffer, status: *mut RustCallStatus) {
            let slice = unsafe { std::slice::from_raw_parts(arg.data, arg.len as usize) };
            let text = std::str::from_utf8(slice).unwrap();
            assert_eq!(text, "{\"client_id\":77}");
            let mut free_st = RustCallStatus::default();
            unsafe {
                test_rb_free(arg, &raw mut free_st);
                (*status).code = 0;
            }
        }

        unsafe extern "C" fn test_invoke_sync(
            arg: RustBuffer,
            status: *mut RustCallStatus,
        ) -> RustBuffer {
            let req_str = unsafe {
                std::str::from_utf8(std::slice::from_raw_parts(arg.data, arg.len as usize))
                    .unwrap()
                    .to_owned()
            };
            let mut free_st = RustCallStatus::default();
            unsafe {
                test_rb_free(arg, &raw mut free_st);
                (*status).code = 0;
            }

            if req_str.contains("\"VaultsList\"") {
                return make_ret_buf(r#"[{"id":"vault-dev-01","title":"Dev"}]"#);
            }
            if req_str.contains("\"SecretsResolve\"") {
                return make_ret_buf(r#""resolved_top_secret_\n_val""#);
            }
            if req_str.contains("\"ItemsGet\"") {
                let current = MOCK_STORE.lock().unwrap().clone().unwrap_or_else(|| {
                    r#"{"id":"item-1","title":"DB","vaultId":"vault-dev-01","category":"API_CREDENTIAL","tags":["secretbridge-managed"],"version":3,"fields":[{"id":"f_existing","title":"OLD_KEY","fieldType":"Concealed","value":"keep_existing_secret_untouched"}]}"#.to_string()
                });
                return make_ret_buf(&current);
            }
            if req_str.contains("\"ItemsPut\"") || req_str.contains("\"ItemsCreate\"") {
                let v: serde_json::Value = serde_json::from_str(&req_str).unwrap();
                let params = &v["invocation"]["parameters"];
                let item = if params.get("item").is_some() {
                    &params["item"]
                } else {
                    params
                };
                *MOCK_STORE.lock().unwrap() = Some(item.to_string());
                return make_ret_buf(&item.to_string());
            }
            make_ret_buf("{}")
        }

        *MOCK_STORE.lock().unwrap() = None;
        ALLOC_LEDGER.lock().unwrap().clear();

        let provider = UniffiCoreVaultProvider::from_test_symbol_table(UniffiSymbolTable {
            rustbuffer_from_bytes: test_rb_from_bytes,
            rustbuffer_free: test_rb_free,
            init_client: test_init_client,
            invoke_sync: test_invoke_sync,
            release_client: test_release_client,
        });

        let tok = MemSecret::from_slice(dummy_op_token().as_bytes()).unwrap();
        let vaults = provider.list_vaults(&tok).unwrap();
        assert_eq!(vaults.len(), 1);
        assert_eq!(vaults[0].id, "vault-dev-01");

        let resolved = provider
            .resolve_ref(
                &tok,
                "vault-dev-01",
                &"op://vault-dev-01/item-1/OLD_KEY".parse().unwrap(),
            )
            .unwrap();
        assert_eq!(resolved.as_bytes(), b"resolved_top_secret_\n_val");

        // Append a new concealed field via byte-span splicing and verify the untouched field's secret survived intact!
        let new_val = MemSecret::from_slice(b"new_spliced_secret_\"quoted\"").unwrap();
        let receipt = provider
            .store_secret(
                &tok,
                "vault-dev-01",
                &CaptureTarget::ExistingItemNewField {
                    item_id: "item-1".into(),
                    field_name: "NEW_KEY".parse().unwrap(),
                },
                &new_val,
                None,
            )
            .unwrap();
        assert_eq!(receipt.item_id, "item-1");

        let saved_json = MOCK_STORE.lock().unwrap().clone().unwrap();
        let saved_val: serde_json::Value = serde_json::from_str(&saved_json).unwrap();
        let fields = saved_val["fields"].as_array().unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0]["value"], "keep_existing_secret_untouched");
        assert_eq!(fields[1]["value"], "new_spliced_secret_\"quoted\"");

        // Every single RustBuffer allocated across FFI must have been freed with zero leaks!
        assert!(
            ALLOC_LEDGER.lock().unwrap().is_empty(),
            "leaked RustBuffers in UniFFI bridge"
        );
    }

    #[test]
    fn hcl_utf8_escaping_and_template_collision_checks_closing_m2() {
        let escaped = escape_hcl_string("caf\u{00e9}/${aws_var}/%{dir}");
        assert_eq!(escaped, "\"caf\u{00e9}/$${aws_var}/%%{dir}\"");
    }

    #[test]
    fn noise_ik_rpc_session_and_templates_end_to_end() {
        let (svc, _, _, _) = build_fixture(true);
        let manifest = sample_manifest();
        let dev: Slug = "dev".parse().unwrap();

        for kind in [
            TemplateKind::Env,
            TemplateKind::WorkflowNative,
            TemplateKind::Workflow1password,
            TemplateKind::Terraform,
            TemplateKind::Cdk,
            TemplateKind::Cloudformation,
        ] {
            let tpl_resp = svc.handle(EnclaveRequest::Template {
                manifest: manifest.clone(),
                environment: dev.clone(),
                kind,
                action_sha: Some("0123456789abcdef0123456789abcdef01234567".parse().unwrap()),
            });
            assert!(tpl_resp.ok, "template {kind:?} failed");
        }

        // End-to-end Noise_IK RPC over stream pair
        let enclave_kp = generate_noise_keypair().unwrap();
        let client_kp = generate_noise_keypair().unwrap();
        let (mut c_stream, s_stream) = std::os::unix::net::UnixStream::pair().unwrap();

        let svc_clone = Arc::clone(&svc);
        let enc_priv = *enclave_kp.private;
        let cli_pub = client_kp.public;
        let srv_handle = thread::spawn(move || {
            serve_noise_connection(s_stream, svc_clone.as_ref(), &enc_priv, &cli_pub).unwrap();
        });

        let mut cli_noise =
            NoiseSession::connect_initiator(&mut c_stream, &client_kp.private, &enclave_kp.public)
                .unwrap();
        let req_bytes = serde_json::to_vec(&EnclaveRequest::Vaults).unwrap();
        cli_noise.send_message(&mut c_stream, &req_bytes).unwrap();
        let resp_bytes = cli_noise.recv_message(&mut c_stream).unwrap();
        let decoded: EnclaveResponse = serde_json::from_slice(&resp_bytes).unwrap();
        assert!(decoded.ok);
        drop(c_stream);
        srv_handle.join().unwrap();
    }
}
