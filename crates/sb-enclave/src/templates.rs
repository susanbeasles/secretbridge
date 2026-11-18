use crate::error::EnclaveError;
use crate::github::GitHubClient;
use crate::mem_secret::MemSecret;
use sb_proto::error::ErrorCode;
use sb_proto::rpc::TemplateKind;
use sb_proto::types::{
    CommitSha40, EnvironmentConfig, GitHubScope, Manifest, SecretName, SecretSpec, SecretState,
    Slug,
};
use serde::Serialize;
use std::collections::BTreeMap;

/// Escapes a value for safe inclusion inside double quotes in a `.env` file (closes S7).
/// Escapes `\`, `"`, `$`, `` ` ``, `\n`, and `\r` so shell/dotenv parsers never evaluate variables
/// or command substitutions.
pub fn escape_dotenv_double_quoted(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('"');
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '$' => out.push_str("\\$"),
            '`' => out.push_str("\\`"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out.push('"');
    out
}

/// Escapes a string literal for Terraform HCL2, neutralizing `\` / `"` and `${` / `%{` directives.
fn escape_hcl_string(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len() + 2);
    out.push('"');
    let bytes = raw.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'\\' => out.push_str("\\\\"),
            b'"' => out.push_str("\\\""),
            b'$' if i + 1 < bytes.len() && bytes[i + 1] == b'{' => {
                out.push_str("$${");
                i += 1;
            }
            b'%' if i + 1 < bytes.len() && bytes[i + 1] == b'{' => {
                out.push_str("%%{");
                i += 1;
            }
            b'\n' => out.push_str("\\n"),
            b'\r' => out.push_str("\\r"),
            b => out.push(char::from(b)),
        }
        i += 1;
    }
    out.push('"');
    out
}

fn json_quoted(raw: &str) -> Result<String, EnclaveError> {
    serde_json::to_string(raw)
        .map_err(|e| EnclaveError::new(ErrorCode::InternalError, format!("json quote failed: {e}")))
}

#[derive(Serialize)]
struct CfnParameter {
    #[serde(rename = "Type")]
    param_type: &'static str,
    #[serde(rename = "Default")]
    default_value: String,
    #[serde(rename = "Description")]
    description: String,
}

#[derive(Serialize)]
struct CfnTemplate {
    #[serde(rename = "AWSTemplateFormatVersion")]
    format_version: &'static str,
    #[serde(rename = "Description")]
    description: &'static str,
    #[serde(rename = "Parameters")]
    parameters: BTreeMap<String, CfnParameter>,
    #[serde(rename = "Resources")]
    resources: BTreeMap<String, serde_json::Value>,
}

pub fn render_template(
    manifest: &Manifest,
    env_name: &Slug,
    kind: TemplateKind,
    action_sha: Option<&CommitSha40>,
    gh_client: &dyn GitHubClient,
    gh_token: Option<&MemSecret>,
) -> Result<String, EnclaveError> {
    manifest.validate()?;
    let Some(env): Option<&EnvironmentConfig> = manifest.environments.get(env_name) else {
        return Err(EnclaveError::new(
            ErrorCode::Validation,
            format!("unknown environment '{env_name}'"),
        ));
    };

    let present_specs: Vec<(&SecretName, &SecretSpec)> = env
        .secrets
        .iter()
        .filter(|(_, spec)| spec.state == SecretState::Present)
        .collect();

    match kind {
        TemplateKind::Env => {
            let mut out = String::new();
            for (name, spec) in present_specs {
                let op_ref = spec.r#ref.as_ref().ok_or_else(|| {
                    EnclaveError::new(ErrorCode::Validation, "missing op:// reference")
                })?;
                out.push_str(name.as_str());
                out.push('=');
                out.push_str(&escape_dotenv_double_quoted(op_ref.as_str()));
                out.push('\n');
            }
            Ok(out)
        }
        TemplateKind::WorkflowNative => {
            let Some(gh) = &env.github else {
                return Err(EnclaveError::new(
                    ErrorCode::Validation,
                    "configure a GitHub destination first",
                ));
            };
            let mut out = String::from(
                "name: Application secrets\non: workflow_dispatch\npermissions: {}\njobs:\n  application:\n    runs-on: ubuntu-24.04\n",
            );
            if gh.scope == GitHubScope::Environment
                && let Some(gh_env) = &gh.environment
            {
                out.push_str("    environment: ");
                out.push_str(&json_quoted(gh_env.as_str())?);
                out.push('\n');
            }
            out.push_str("    steps:\n      - name: Run application\n        env:\n");
            for (name, spec) in present_specs {
                if spec.github {
                    out.push_str("          ");
                    out.push_str(name.as_str());
                    out.push_str(": ${{ secrets.");
                    out.push_str(name.as_str());
                    out.push_str(" }}\n");
                }
            }
            out.push_str(
                "        run: |\n          # Replace with your application command. Never echo secret values.\n          true\n",
            );
            Ok(out)
        }
        TemplateKind::Workflow1password => {
            let resolved_sha = match action_sha {
                Some(sha) => sha.clone(),
                None => gh_client.resolve_load_secrets_action_sha(gh_token)?,
            };
            let mut out = String::from(
                "name: 1Password application secrets\non: workflow_dispatch\npermissions: {}\njobs:\n  application:\n    runs-on: ubuntu-24.04\n",
            );
            if let Some(gh) = &env.github
                && gh.scope == GitHubScope::Environment
                && let Some(gh_env) = &gh.environment
            {
                out.push_str("    environment: ");
                out.push_str(&json_quoted(gh_env.as_str())?);
                out.push('\n');
            }
            out.push_str("    steps:\n      - name: Load secrets\n        uses: 1Password/load-secrets-action@");
            out.push_str(resolved_sha.as_str());
            out.push_str(
                "\n        with:\n          export-env: true\n        env:\n          OP_SERVICE_ACCOUNT_TOKEN: ${{ secrets.OP_SERVICE_ACCOUNT_TOKEN }}\n",
            );
            for (name, spec) in present_specs {
                if name.as_str() == "OP_SERVICE_ACCOUNT_TOKEN" {
                    continue;
                }
                let op_ref = spec.r#ref.as_ref().ok_or_else(|| {
                    EnclaveError::new(ErrorCode::Validation, "missing op:// reference")
                })?;
                out.push_str("          ");
                out.push_str(name.as_str());
                out.push_str(": ");
                out.push_str(&json_quoted(op_ref.as_str())?);
                out.push('\n');
            }
            out.push_str(
                "      - name: Run application\n        run: |\n          # Replace with your application command.\n          true\n",
            );
            Ok(out)
        }
        TemplateKind::Terraform | TemplateKind::Cdk | TemplateKind::Cloudformation => {
            let Some(aws) = &env.aws else {
                return Err(EnclaveError::new(
                    ErrorCode::Validation,
                    "configure an AWS destination first",
                ));
            };
            let aws_entries: Vec<(&SecretName, String)> = present_specs
                .into_iter()
                .filter(|(_, spec)| spec.aws)
                .map(|(name, _)| (name, format!("{}{}", aws.prefix.as_str(), name.as_str())))
                .collect();

            match kind {
                TemplateKind::Terraform => {
                    let mut out = String::from(
                        "# Metadata only: fetching secret values with Terraform would put them in state.\n",
                    );
                    for (name, resource) in aws_entries {
                        let tf_ident = name.as_str().to_ascii_lowercase();
                        out.push_str("data \"aws_secretsmanager_secret\" \"");
                        out.push_str(&tf_ident);
                        out.push_str("\" {\n  name = ");
                        out.push_str(&escape_hcl_string(&resource));
                        out.push_str("\n}\n\n");
                    }
                    Ok(out)
                }
                TemplateKind::Cdk => {
                    let mut out = String::from(
                        "import { Secret } from 'aws-cdk-lib/aws-secretsmanager';\n\n// Inside your stack constructor. Give runtime roles read access as needed.\n",
                    );
                    for (name, resource) in aws_entries {
                        let ts_ident = name.as_str().to_ascii_lowercase();
                        out.push_str("const secret_");
                        out.push_str(&ts_ident);
                        out.push_str(" = Secret.fromSecretNameV2(this, ");
                        out.push_str(&json_quoted(name.as_str())?);
                        out.push_str(", ");
                        out.push_str(&json_quoted(&resource)?);
                        out.push_str(");\n");
                    }
                    Ok(out)
                }
                TemplateKind::Cloudformation => {
                    let mut parameters = BTreeMap::new();
                    for (idx, (name, resource)) in aws_entries.into_iter().enumerate() {
                        let key = format!("Secret{}", idx + 1);
                        parameters.insert(
                            key,
                            CfnParameter {
                                param_type: "String",
                                default_value: resource,
                                description: name.as_str().to_string(),
                            },
                        );
                    }
                    let tpl = CfnTemplate {
                        format_version: "2010-09-09",
                        description: "Secret name parameters; runtime consumers resolve values.",
                        parameters,
                        resources: BTreeMap::new(),
                    };
                    let mut serialized = serde_json::to_string_pretty(&tpl).map_err(|e| {
                        EnclaveError::new(
                            ErrorCode::InternalError,
                            format!("cloudformation serialization failed: {e}"),
                        )
                    })?;
                    serialized.push('\n');
                    Ok(serialized)
                }
                _ => unreachable!(),
            }
        }
    }
}
