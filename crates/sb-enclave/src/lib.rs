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
    use crate::github::InMemoryGitHubClient;
    use crate::service::EnclaveService;
    use crate::vault::InMemoryVaultProvider;
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
    use std::sync::Arc;
    use std::thread;

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
        let vault = Arc::new(InMemoryVaultProvider::new(
            "ops_secret_token_123",
            can_create_vaults,
        ));
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
                op_service_account_token: Some("ops_secret_token_123".into()),
                github_token: Some("ghp_test_token_456".into()),
                aws_access_key_id: Some("AKIAIOSFODNN7EXAMPLE".into()),
                aws_secret_access_key: Some("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY".into()),
                aws_session_token: None,
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
    fn plan_apply_verifies_hmac_ownership_freshness_and_reports_partial_failures_closing_s4_s6_s8()
    {
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

        // Explicitly adopt AWS secret
        let adopt_resp = svc.handle(EnclaveRequest::AdoptAws {
            manifest: manifest.clone(),
            environment: dev.clone(),
            name: "DATABASE_URL".parse::<SecretName>().unwrap(),
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

        // Mutate manifest after plan -> rejected as StalePlan (TOCTOU closed)
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

        // Simulate partial apply failure on the second AWS secret (`API_KEY` happens before `DATABASE_URL` in BTreeMap order, so fail `DATABASE_URL`)
        aws.set_fail_on_secret(Some("secretbridge/dev/DATABASE_URL".into()));
        let partial_resp = svc.handle(EnclaveRequest::Apply {
            manifest: manifest.clone(),
            signed_plan,
        });
        assert!(partial_resp.ok);
        let Some(EnclaveResult::Applied(report)) = partial_resp.result else {
            panic!("expected ApplyReport");
        };
        assert!(!report.complete);
        assert!(report.results.iter().any(|r| r.succeeded));
        assert!(report.results.iter().any(|r| !r.succeeded));

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
        let gh_target = manifest.environments[&dev].github.as_ref().unwrap();
        let gh_db = gh.decrypt_stored_secret(gh_target, "DATABASE_URL").unwrap();
        assert_eq!(&gh_db[..], b"postgres://app:supersecret@db:5432/app");
        assert!(aws.stored_value_equals(
            "secretbridge/dev/DATABASE_URL",
            b"postgres://app:supersecret@db:5432/app"
        ));
        assert!(aws.stored_value_equals("secretbridge/dev/API_KEY", b"sk_live_987654321"));

        // Verify Delete action when state transitions to Absent
        manifest.environments.get_mut(&dev).unwrap().secrets.insert(
            "API_KEY".parse().unwrap(),
            sb_proto::types::SecretSpec {
                r#ref: None::<OpRef>,
                state: SecretState::Absent,
                group: None,
                github: true,
                aws: true,
            },
        );
        let del_plan_resp = svc.handle(EnclaveRequest::Plan {
            manifest: manifest.clone(),
            environment: dev,
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
            manifest,
            signed_plan: del_plan,
        });
        assert!(del_apply.ok);
        let _ = (TAG_PROJECT, TAG_ENVIRONMENT);
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
