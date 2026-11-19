pub mod aws;
pub mod dhcp;
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
        ForeignBytes, InMemoryVaultProvider, RustBuffer, RustCallStatus, UniffiBufCall,
        UniffiCoreVaultProvider, UniffiFutureContinuationCallback, UniffiSymbolTable,
        VaultProvider, unescape_json_string_to_mem_secret,
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
                allow_unmanaged_github_overwrite: false,
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

        // Verify pre-existing UNMANAGED GitHub secret overwrite is refused unless allow_unmanaged_github_overwrite=true (`V2-M1`)
        let unmanaged_name: SecretName = "LEGACY_CI_TOKEN".parse().unwrap();
        gh.seed_unmanaged_secret(&gh_target, &unmanaged_name, b"preexisting")
            .unwrap();
        manifest.environments.get_mut(&dev).unwrap().secrets.insert(
            unmanaged_name.clone(),
            sb_proto::types::SecretSpec {
                r#ref: Some("op://vault-dev-01/item-db/url".parse().unwrap()),
                state: SecretState::Present,
                group: None,
                github: true,
                aws: false,
                allow_unmanaged_github_delete: false,
                allow_unmanaged_github_overwrite: false,
            },
        );
        let refused_gh_overwrite = svc.handle(EnclaveRequest::Plan {
            manifest: manifest.clone(),
            environment: dev.clone(),
        });
        assert!(!refused_gh_overwrite.ok);
        assert_eq!(
            refused_gh_overwrite.error.unwrap().code,
            ErrorCode::OwnershipConflict
        );

        manifest
            .environments
            .get_mut(&dev)
            .unwrap()
            .secrets
            .get_mut(&unmanaged_name)
            .unwrap()
            .allow_unmanaged_github_overwrite = true;
        assert!(
            svc.handle(EnclaveRequest::Plan {
                manifest: manifest.clone(),
                environment: dev.clone(),
            })
            .ok
        );

        // Verify pre-existing UNMANAGED GitHub secret deletion is refused unless allow_unmanaged_github_delete=true (`H3`)
        manifest.environments.get_mut(&dev).unwrap().secrets.insert(
            unmanaged_name.clone(),
            sb_proto::types::SecretSpec {
                r#ref: None,
                state: SecretState::Absent,
                group: None,
                github: true,
                aws: false,
                allow_unmanaged_github_delete: false,
                allow_unmanaged_github_overwrite: false,
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
        // 1. PublicIpOnlyResolver filter (`C1`, `H4`, `V2-H5`)
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
            "64:ff9b::a9fe:a9fe", // NAT64 Well-Known Prefix
            "64:ff9b:1::1",       // NAT64 Local-Use Prefix
            "2002:7f00:1::1",     // 6to4 loopback
            "2001:0::1",          // Teredo
            "::0a00:0202",        // IPv4-compatible ::/96
        ] {
            let ip: IpAddr = blocked.parse().unwrap();
            assert!(!is_public_unicast_ip(ip), "{blocked} must be blocked");
        }
        for public_ip in ["1.1.1.1", "140.82.112.4", "2606:4700:4700::1111"] {
            let ip: IpAddr = public_ip.parse().unwrap();
            assert!(is_public_unicast_ip(ip), "{public_ip} must be allowed");
        }

        // 2. Untrusted manifest pointing at `evil.example.com` or unauthorized owner/account (`C1`, `C2`, `V2-H5`)
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

        // Default-empty owner or AWS account allowlists must fail closed (`V2-H5`)
        let _ = svc.handle(EnclaveRequest::ConfigureSession {
            credentials: SessionCredentialsInput {
                op_service_account_token: Some(dummy_op_token()),
                github_token: Some(dummy_gh_token()),
                aws_access_key_id: Some(dummy_aws_ak()),
                aws_secret_access_key: Some(dummy_aws_sk()),
                aws_session_token: None,
                allowed_github_hosts: vec!["github.com".into()],
                allowed_github_owners: Vec::new(),
                allowed_aws_account_ids: vec!["123456789012".into()],
            },
        });
        let empty_owner_plan = svc.handle(EnclaveRequest::Plan {
            manifest: sample_manifest(),
            environment: dev.clone(),
        });
        assert!(!empty_owner_plan.ok);
        assert_eq!(
            empty_owner_plan.error.unwrap().code,
            ErrorCode::Unauthorized
        );

        // Enterprise GHES session must require explicit action_sha for Workflow1password (`V2-M2`)
        let _ = svc.handle(EnclaveRequest::ConfigureSession {
            credentials: SessionCredentialsInput {
                op_service_account_token: Some(dummy_op_token()),
                github_token: Some(dummy_gh_token()),
                aws_access_key_id: None,
                aws_secret_access_key: None,
                aws_session_token: None,
                allowed_github_hosts: vec!["ghe.acme.com".into()],
                allowed_github_owners: vec!["susanbeasles".into()],
                allowed_aws_account_ids: Vec::new(),
            },
        });
        let mut ghes_manifest = sample_manifest();
        ghes_manifest
            .environments
            .get_mut(&dev)
            .unwrap()
            .github
            .as_mut()
            .unwrap()
            .host = "ghe.acme.com".parse().unwrap();
        let unpinned_ghes_tpl = svc.handle(EnclaveRequest::Template {
            manifest: ghes_manifest,
            environment: dev.clone(),
            kind: TemplateKind::Workflow1password,
            action_sha: None,
        });
        assert!(!unpinned_ghes_tpl.ok);
        assert_eq!(unpinned_ghes_tpl.error.unwrap().code, ErrorCode::Validation);

        // Restore valid allowlisted session before testing atomic wipe & key rotation
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
        static FUTURE_LEDGER: Mutex<BTreeMap<u64, (usize, String)>> = Mutex::new(BTreeMap::new());
        static RELEASED_CLIENTS: Mutex<Vec<u64>> = Mutex::new(Vec::new());
        static MOCK_STORE: Mutex<Option<String>> = Mutex::new(None);

        // Verify malformed `\u` adjacent to 4-byte UTF-8 never panics (`V2-C2`)
        assert!(unescape_json_string_to_mem_secret("\"\\u12\u{1F510}\"".as_bytes()).is_err());
        assert!(
            unescape_json_string_to_mem_secret("\"\\uD83D\\u12\u{1F510}\"".as_bytes()).is_err()
        );

        unsafe extern "C" fn test_rb_from_bytes(
            bytes: ForeignBytes,
            status: *mut RustCallStatus,
        ) -> RustBuffer {
            unsafe {
                (*status).code = 0;
            }
            let len = bytes.len.max(0) as usize;
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

        // Authentic Mozilla UniFFI async `init_client(RustBuffer) -> u64` (`RustFuture` handle, `V2-C2`)
        unsafe extern "C" fn test_init_client_async(arg: RustBuffer) -> u64 {
            let slice = unsafe { std::slice::from_raw_parts(arg.data, arg.len as usize) };
            let text = std::str::from_utf8(slice).unwrap();
            assert!(text.contains("\"serviceAccountToken\":"));
            let mut free_st = RustCallStatus::default();
            unsafe {
                test_rb_free(arg, &raw mut free_st);
            }
            let mut futs = FUTURE_LEDGER.lock().unwrap();
            let handle = (futs.len() as u64) + 100;
            futs.insert(handle, (0, "77".to_string()));
            handle
        }

        unsafe extern "C" fn test_future_poll(
            handle: u64,
            cb: UniffiFutureContinuationCallback,
            cb_data: u64,
        ) {
            let poll_code = {
                let mut futs = FUTURE_LEDGER.lock().unwrap();
                let (polls, _) = futs.get_mut(&handle).expect("valid future handle");
                *polls += 1;
                // Exercise multi-step async wakeup (`1 = WAKE` on first poll, `0 = READY` on second poll)
                if *polls == 1 { 1i8 } else { 0i8 }
            };
            thread::spawn(move || {
                cb(cb_data, poll_code);
            });
        }

        unsafe extern "C" fn test_future_complete(
            handle: u64,
            status: *mut RustCallStatus,
        ) -> RustBuffer {
            unsafe {
                (*status).code = 0;
            }
            let futs = FUTURE_LEDGER.lock().unwrap();
            let (polls, payload) = futs.get(&handle).expect("valid future handle");
            assert!(*polls >= 2, "must not complete before READY");
            make_ret_buf(payload)
        }

        unsafe extern "C" fn test_future_free(handle: u64) {
            FUTURE_LEDGER
                .lock()
                .unwrap()
                .remove(&handle)
                .expect("double-free or unknown UniFFI future handle");
        }

        unsafe extern "C" fn test_release_client(client_id: u64, status: *mut RustCallStatus) {
            assert_eq!(client_id, 77);
            RELEASED_CLIENTS.lock().unwrap().push(client_id);
            unsafe {
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
        FUTURE_LEDGER.lock().unwrap().clear();
        RELEASED_CLIENTS.lock().unwrap().clear();

        let provider = UniffiCoreVaultProvider::from_test_symbol_table(UniffiSymbolTable {
            rustbuffer_from_bytes: test_rb_from_bytes,
            rustbuffer_free: test_rb_free,
            init_client: UniffiBufCall::Async {
                start: test_init_client_async,
                poll: test_future_poll,
                complete: test_future_complete,
                free: test_future_free,
            },
            invoke: UniffiBufCall::Sync(test_invoke_sync),
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

        // Every single RustBuffer and RustFuture handle allocated across FFI must have been freed!
        assert!(
            ALLOC_LEDGER.lock().unwrap().is_empty(),
            "leaked RustBuffers in UniFFI bridge"
        );
        assert!(
            FUTURE_LEDGER.lock().unwrap().is_empty(),
            "leaked RustFuture handles in UniFFI bridge"
        );
        assert_eq!(RELEASED_CLIENTS.lock().unwrap().len(), 3);
    }

    #[test]
    fn hcl_utf8_escaping_and_template_collision_checks_closing_m2() {
        let escaped = escape_hcl_string("caf\u{00e9}/${aws_var}/%{dir}");
        assert_eq!(escaped, "\"caf\u{00e9}/$${aws_var}/%%{dir}\"");

        // Multi-sigil `$${foo}` / `$$${bar}` / `%%{baz}` must never produce active `${...}` (`V2-M2`)
        let multi = escape_hcl_string("$${foo} / $$${bar} / %%{baz}");
        assert_eq!(multi, "\"$$\\u007bfoo} / $$$\\u007bbar} / %%\\u007bbaz}\"");
        assert!(!multi.contains("${"));
        assert!(!multi.contains("%{"));
    }

    #[test]
    fn noise_ik_rpc_session_and_templates_end_to_end() {
        let (svc, _, _, _) = build_fixture(true);
        let dev: Slug = "dev".parse().unwrap();
        let mut manifest = sample_manifest();
        manifest
            .bind_secret(
                &dev,
                "NULL".parse().unwrap(),
                "op://vault-dev-01/app-db/null_tok".parse().unwrap(),
                None,
                Some(true),
                Some(true),
            )
            .unwrap();
        manifest
            .bind_secret(
                &dev,
                "TRUE".parse().unwrap(),
                "op://vault-dev-01/app-db/true_tok".parse().unwrap(),
                None,
                Some(true),
                Some(true),
            )
            .unwrap();

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
            let Some(EnclaveResult::TemplateRendered { content, .. }) = tpl_resp.result else {
                panic!("expected TemplateRendered for {kind:?}");
            };
            match kind {
                TemplateKind::WorkflowNative => {
                    assert!(content.contains("\"NULL\": ${{ secrets.NULL }}"));
                    assert!(content.contains("\"TRUE\": ${{ secrets.TRUE }}"));
                }
                TemplateKind::Workflow1password => {
                    assert!(content.contains("\"NULL\": \"op://vault-dev-01/app-db/null_tok\""));
                    assert!(content.contains("\"TRUE\": \"op://vault-dev-01/app-db/true_tok\""));
                }
                TemplateKind::Cloudformation => {
                    let cfn_json: serde_json::Value = serde_json::from_str(&content).unwrap();
                    let resources = cfn_json["Resources"].as_object().unwrap();
                    assert!(!resources.is_empty());
                    assert_eq!(
                        resources["SecretBridgeReadSecretsPolicy"]["Type"],
                        "AWS::IAM::ManagedPolicy"
                    );
                }
                _ => {}
            }
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

    #[test]
    fn dhcpv4_cmdline_vsock_port_and_ephemeral_memsecret_enclave_identity() {
        use crate::dhcp::{
            DHCP_ACK, DHCP_OFFER, DhcpLeaseSchedule, build_dhcpv4_discover, build_dhcpv4_request,
            parse_dhcpv4_reply,
        };
        use crate::vsock::{
            cmdline_has_token, extract_cmdline_egress_vsock_port, extract_cmdline_vsock_port,
            generate_ephemeral_enclave_identity,
        };
        use std::time::{Duration, Instant};

        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let xid = 0xA1B2_C3D4;
        let discover = build_dhcpv4_discover(xid, mac);
        assert_eq!(discover[0], 1);
        assert_eq!(&discover[28..34], &mac);
        assert_eq!(&discover[236..240], &[99, 130, 83, 99]);

        let mut reply = vec![0u8; 280];
        reply[0] = 2; // BOOTREPLY
        reply[1] = 1;
        reply[2] = 6;
        reply[4..8].copy_from_slice(&xid.to_be_bytes());
        reply[16..20].copy_from_slice(&[192, 168, 64, 2]);
        reply[28..34].copy_from_slice(&mac);
        reply[236..240].copy_from_slice(&[99, 130, 83, 99]);
        let opts = [
            53, 1, DHCP_OFFER, // Msg type = OFFER
            54, 4, 192, 168, 64, 1, // Server ID
            51, 4, 0, 0, 7, 8, // Lease Time = 1800s
            1, 4, 255, 255, 255, 0, // Subnet mask
            3, 4, 192, 168, 64, 1, // Router
            6, 4, 192, 168, 64, 1, // DNS
            255,
        ];
        reply[240..240 + opts.len()].copy_from_slice(&opts);

        let (kind, lease) = parse_dhcpv4_reply(&reply, xid, mac).unwrap();
        assert_eq!(kind, DHCP_OFFER);
        assert_eq!(lease.yiaddr, [192, 168, 64, 2]);
        assert_eq!(lease.lease_time_secs, 1_800);
        assert_eq!(lease.subnet_mask, [255, 255, 255, 0]);
        assert_eq!(lease.router, Some([192, 168, 64, 1]));
        assert_eq!(lease.dns_servers, vec![[192, 168, 64, 1]]);
        assert_eq!(lease.server_id, Some([192, 168, 64, 1]));

        let t0 = Instant::now();
        let mut sched = DhcpLeaseSchedule::new(lease.clone(), t0);
        assert_eq!(
            sched.wait_duration_until_next_action(t0),
            Duration::from_secs(900)
        );
        assert_eq!(sched.t2_at.duration_since(t0), Duration::from_secs(1_575));
        assert_eq!(
            sched.expires_at.duration_since(t0),
            Duration::from_secs(1_800)
        );
        assert_eq!(
            sched.attempt_deadline(t0 + Duration::from_secs(1_799)),
            t0 + Duration::from_secs(1_800)
        );
        // Failure at T1 (+900s) retries halfway to T2 (+1237.5s), not another full 900s (+1800s)
        assert!(!sched.record_renewal_failure(t0 + Duration::from_secs(900)));
        assert!(sched.next_attempt_at < sched.t2_at);
        // Failure during T2 rebinding (+1600s) retries halfway to expiry (+1700s), bounded by expires_at
        let t_rebind = t0 + Duration::from_secs(1_600);
        assert!(sched.is_rebinding(t_rebind));
        assert!(!sched.record_renewal_failure(t_rebind));
        assert_eq!(sched.next_attempt_at, t0 + Duration::from_secs(1_700));
        // At or after hard expiry (+1800s), signals immediate stale-config withdrawal
        assert!(sched.record_renewal_failure(t0 + Duration::from_secs(1_800)));
        assert!(sched.is_expired(t0 + Duration::from_secs(1_800)));

        // Short 30s leases must not be lengthened to 60s, and 0s leases must be rejected
        let mut short_reply = reply.clone();
        short_reply[251..255].copy_from_slice(&30u32.to_be_bytes());
        let (_, short_lease) = parse_dhcpv4_reply(&short_reply, xid, mac).unwrap();
        assert_eq!(short_lease.lease_time_secs, 30);
        let short_sched = DhcpLeaseSchedule::new(short_lease, t0);
        assert_eq!(
            short_sched.t1_at.duration_since(t0),
            Duration::from_secs(15)
        );
        assert_eq!(
            short_sched.expires_at.duration_since(t0),
            Duration::from_secs(30)
        );
        short_reply[251..255].copy_from_slice(&0u32.to_be_bytes());
        assert!(parse_dhcpv4_reply(&short_reply, xid, mac).is_none());

        let req = build_dhcpv4_request(xid, mac, lease.yiaddr, lease.server_id);
        assert_eq!(req[0], 1);
        reply[242] = DHCP_ACK;
        let (ack_kind, _) = parse_dhcpv4_reply(&reply, xid, mac).unwrap();
        assert_eq!(ack_kind, DHCP_ACK);
        assert!(parse_dhcpv4_reply(&reply, xid ^ 1, mac).is_none());

        let cmdline =
            "console=hvc0 ip=dhcp sb.vsock_port=6222 sb.egress_vsock_port=6223 sb.client_pubkey=aa";
        assert_eq!(extract_cmdline_vsock_port(cmdline).unwrap(), Some(6222));
        assert_eq!(
            extract_cmdline_egress_vsock_port(cmdline).unwrap(),
            Some(6223)
        );
        assert!(!cmdline_has_token(cmdline, "sb.net_fallback=qemu_slirp"));
        assert!(cmdline_has_token(
            "console=ttyS0 sb.net_fallback=qemu_slirp",
            "sb.net_fallback=qemu_slirp"
        ));
        assert!(extract_cmdline_vsock_port("sb.vsock_port=0").is_err());
        assert!(extract_cmdline_vsock_port("sb.vsock_port=70000").is_err());
        assert!(extract_cmdline_vsock_port("sb.vsock_port=bad").is_err());

        // Ephemeral guest identity lives strictly inside `MemSecret` (`memfd_secret`/`mlock`)
        let id_a = generate_ephemeral_enclave_identity().unwrap();
        let id_b = generate_ephemeral_enclave_identity().unwrap();
        assert_eq!(id_a.private.len(), 32);
        assert_ne!(id_a.public, id_b.public);
        assert_ne!(id_a.public, [0u8; 32]);
    }
}
