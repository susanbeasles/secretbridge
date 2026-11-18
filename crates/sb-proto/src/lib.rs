#![forbid(unsafe_code)]

pub mod crypto;
pub mod error;
pub mod plan;
pub mod rpc;
pub mod types;

#[cfg(test)]
mod tests {
    use super::crypto::{
        NoiseSession, generate_noise_keypair, generate_sealed_box_keypair, seal_base64,
        unseal_base64,
    };
    use super::plan::{PlanAction, PlanSigner, PlannedOp, UnsignedPlan, sha256_hex};
    use super::types::{
        AwsAccountId, AwsRegion, AwsSecretPrefix, GitHubEnvName, GitHubHost, GitHubRepoFullName,
        GitHubScope, GitHubTarget, Manifest, OpRef, RecoveryDays, SecretName, Slug,
    };
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD as B64;
    use std::io::Cursor;
    use std::thread;

    fn sample_valid_manifest_json() -> &'static str {
        r#"{
          "version": 2,
          "project": "payments-api",
          "account": "vespoli.1password.com",
          "environments": {
            "dev": {
              "vault": "vault-dev-01",
              "secrets": {
                "DATABASE_URL": {
                  "ref": "op://vault-dev-01/item123/sec1/field456",
                  "state": "present",
                  "group": "database",
                  "github": true,
                  "aws": true
                }
              },
              "github": {
                "scope": "environment",
                "host": "github.com",
                "repository": "susanbeasles/secretbridge",
                "environment": "dev-us-west"
              },
              "aws": {
                "profile": "dev-sso",
                "region": "us-west-2",
                "account_id": "123456789012",
                "prefix": "payments/dev/",
                "recovery_days": 14
              }
            }
          }
        }"#
    }

    #[test]
    fn rejects_manifest_with_v010_tools_key_closing_s1() {
        let malicious = r#"{
          "version": 1,
          "project": "demo",
          "account": "acct",
          "tools": { "op": "/tmp/evil.sh" },
          "environments": {
            "dev": { "vault": "v1", "secrets": {} }
          }
        }"#;
        let err = Manifest::from_json_str(malicious).unwrap_err();
        assert!(err.to_string().contains("unknown field `tools`"));
    }

    #[test]
    fn rejects_repo_traversal_and_unicode_homoglyphs_closing_s2() {
        assert!("../../evil".parse::<GitHubRepoFullName>().is_err());
        assert!("owner/..".parse::<GitHubRepoFullName>().is_err());
        assert!("owner/repo/extra".parse::<GitHubRepoFullName>().is_err());
        // Cyrillic small letter 'a' (U+0430) must be rejected by strict 7-bit ASCII check
        assert!(
            "susanbe\u{0430}sles/repo"
                .parse::<GitHubRepoFullName>()
                .is_err()
        );
        assert!("prod/../../admin".parse::<GitHubEnvName>().is_err());

        let gh = GitHubTarget {
            scope: GitHubScope::Environment,
            host: GitHubHost::default(),
            repository: Some("susanbeasles/secretbridge".parse().unwrap()),
            organization: None,
            environment: Some("prod blue+green".parse().unwrap()),
            repositories: None,
        };
        assert_eq!(
            gh.secrets_endpoint_path().unwrap(),
            "repos/susanbeasles/secretbridge/environments/prod%20blue%2Bgreen/secrets"
        );
    }

    #[test]
    fn rejects_flag_injection_host_closing_s3() {
        assert!("-evil.flag".parse::<GitHubHost>().is_err());
        assert!("https://github.com".parse::<GitHubHost>().is_err());
        assert!("github.com:8443".parse::<GitHubHost>().is_err());
        assert_eq!(
            "GitHub.COM".parse::<GitHubHost>().unwrap().as_str(),
            "github.com"
        );
    }

    #[test]
    fn rejects_op_ref_injection_and_vault_mismatch_closing_s7_and_s10() {
        assert!("op://v/i/f\"\nMALICIOUS=1".parse::<OpRef>().is_err());
        assert!("op://v/../f".parse::<OpRef>().is_err());
        assert!("op://v/-flag/f".parse::<OpRef>().is_err());

        let mut m = Manifest::from_json_str(sample_valid_manifest_json()).unwrap();
        let dev: Slug = "dev".parse().unwrap();
        let wrong_ref: OpRef = "op://other-vault/item123/field456".parse().unwrap();
        let res = m.bind_secret(
            &dev,
            "API_KEY".parse::<SecretName>().unwrap(),
            wrong_ref,
            None,
            None,
            None,
        );
        assert!(res.is_err());
    }

    #[test]
    fn bind_secret_preserves_existing_cloud_flags_fixing_b7() {
        let mut m = Manifest::from_json_str(sample_valid_manifest_json()).unwrap();
        let dev: Slug = "dev".parse().unwrap();
        let db_name: SecretName = "DATABASE_URL".parse().unwrap();
        m.environments
            .get_mut(&dev)
            .unwrap()
            .secrets
            .get_mut(&db_name)
            .unwrap()
            .github = false;

        let updated_ref: OpRef = "op://vault-dev-01/item123/sec1/field789".parse().unwrap();
        m.bind_secret(&dev, db_name.clone(), updated_ref, None, None, None)
            .unwrap();

        let spec = &m.environments[&dev].secrets[&db_name];
        assert!(!spec.github);
        assert!(spec.aws);
        assert_eq!(spec.group.as_ref().unwrap().as_str(), "database");
    }

    #[test]
    fn validates_aws_fields_and_recovery_bounds_closing_s11() {
        assert!(RecoveryDays::new(6).is_err());
        assert!(RecoveryDays::new(31).is_err());
        assert_eq!(RecoveryDays::new(7).unwrap().get(), 7);
        assert!("us-west-2".parse::<AwsRegion>().is_ok());
        assert!("us-west-0".parse::<AwsRegion>().is_err());
        assert!("123456789012".parse::<AwsAccountId>().is_ok());
        assert!("12345678901a".parse::<AwsAccountId>().is_err());
        assert!("app/prod/".parse::<AwsSecretPrefix>().is_ok());
        assert!("app/../prod/".parse::<AwsSecretPrefix>().is_err());
        assert!("app/prod".parse::<AwsSecretPrefix>().is_err());
    }

    #[test]
    fn plan_hmac_rejects_tampering_and_expiry_closing_s4() {
        let m = Manifest::from_json_str(sample_valid_manifest_json()).unwrap();
        let signer = PlanSigner::new([0x42; 32], 300);
        let unsigned = UnsignedPlan {
            version: 2,
            environment: "dev".parse().unwrap(),
            manifest_digest: sha256_hex(&m).unwrap(),
            source_revision_digest: "rev-abc".into(),
            aws_identity: None,
            issued_at_unix_secs: 1_000,
            operations: vec![PlannedOp::Github {
                name: "DATABASE_URL".parse().unwrap(),
                action: PlanAction::Set,
                destination: m.environments[&"dev".parse::<Slug>().unwrap()]
                    .github
                    .clone()
                    .unwrap(),
                observed_updated_at: None,
            }],
        };
        let mut signed = signer.sign(unsigned).unwrap();
        assert!(signer.verify(&signed, 1_120).is_ok());
        // Expired
        assert!(signer.verify(&signed, 1_301).is_err());
        // Tampered environment
        signed.plan.source_revision_digest = "rev-evil".into();
        assert!(signer.verify(&signed, 1_120).is_err());
    }

    #[test]
    fn sealed_box_roundtrip_matches_libsodium_wire_overhead() {
        let (sk, pk) = generate_sealed_box_keypair();
        let pk_b64 = B64.encode(pk);
        let secret = b"sk_live_super_secret_value_12345";
        let sealed_b64 = seal_base64(&pk_b64, secret).unwrap();
        let raw_ct = B64.decode(&sealed_b64).unwrap();
        // libsodium crypto_box_seal adds 32-byte ephemeral pubkey + 16-byte Poly1305 tag = 48 bytes
        assert_eq!(raw_ct.len(), secret.len() + 48);
        let opened = unseal_base64(&sk, &sealed_b64).unwrap();
        assert_eq!(&opened[..], secret);
    }

    #[test]
    fn noise_ik_mutually_authenticates_and_chunks_large_payloads() {
        let enclave_kp = generate_noise_keypair().unwrap();
        let client_kp = generate_noise_keypair().unwrap();
        let rogue_kp = generate_noise_keypair().unwrap();

        let (mut c_sock, mut s_sock) = std::os::unix::net::UnixStream::pair().unwrap();
        let enclave_priv = *enclave_kp.private;
        let enclave_pub = enclave_kp.public;
        let client_priv = *client_kp.private;
        let client_pub = client_kp.public;

        let server = thread::spawn(move || {
            let mut session =
                NoiseSession::accept_responder(&mut s_sock, &enclave_priv, &client_pub).unwrap();
            let msg = session.recv_message(&mut s_sock).unwrap();
            session.send_message(&mut s_sock, &msg).unwrap();
        });

        let mut client =
            NoiseSession::connect_initiator(&mut c_sock, &client_priv, &enclave_pub).unwrap();
        // 150 KiB payload exercises multi-chunk AEAD framing
        let large_payload = vec![b'A'; 150_000];
        client.send_message(&mut c_sock, &large_payload).unwrap();
        let echoed = client.recv_message(&mut c_sock).unwrap();
        assert_eq!(&echoed[..], &large_payload[..]);
        server.join().unwrap();

        // Rogue client with unauthorized static key must be rejected by enclave responder
        let (mut rc_sock, mut rs_sock) = std::os::unix::net::UnixStream::pair().unwrap();
        let rogue_priv = *rogue_kp.private;
        let rogue_handle = thread::spawn(move || {
            let _ = NoiseSession::connect_initiator(&mut rc_sock, &rogue_priv, &enclave_pub);
        });
        let err =
            NoiseSession::accept_responder(&mut rs_sock, &enclave_kp.private, &client_kp.public);
        assert!(err.is_err());
        drop(rs_sock);
        let _ = rogue_handle.join();
        let _ = Cursor::new(Vec::<u8>::new());
    }
}
