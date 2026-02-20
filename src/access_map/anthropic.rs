use anyhow::{anyhow, Context, Result};
use reqwest::{header, Client};
use serde::Deserialize;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    build_recommendations, AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary,
    ResourceExposure, RoleBinding, Severity,
};

const ANTHROPIC_API: &str = "https://api.anthropic.com/v1";
const ANTHROPIC_VERSION: &str = "2023-06-01";
const MAX_MODEL_RESOURCES: usize = 50;

#[derive(Debug, Deserialize, Default, Clone)]
struct AnthropicModelsResponse {
    #[serde(default)]
    data: Vec<AnthropicModel>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct AnthropicModel {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    display_name: Option<String>,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read Anthropic token from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!("Anthropic access-map requires a validated token from scan results"));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Anthropic HTTP client")?;

    let mut risk_notes = Vec::new();
    let mut roles = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut resources = Vec::new();

    let models = list_models(&client, token).await.unwrap_or_else(|err| {
        warn!("Anthropic access-map: model enumeration failed: {err}");
        risk_notes.push(format!("Model enumeration failed: {err}"));
        Vec::new()
    });

    let token_kind = detect_token_type(token);
    roles.push(RoleBinding {
        name: format!("token_type:{token_kind}"),
        source: "anthropic".into(),
        permissions: vec![format!("token:{token_kind}")],
    });
    permissions.read_only.push("models:list".to_string());

    for model in models.iter().take(MAX_MODEL_RESOURCES) {
        let model_name = model
            .id
            .clone()
            .or_else(|| model.display_name.clone())
            .unwrap_or_else(|| "unknown_model".to_string());
        resources.push(ResourceExposure {
            resource_type: "model".into(),
            name: model_name,
            permissions: vec!["model:read".to_string()],
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Model accessible to this Anthropic key".to_string(),
        });
    }

    if models.len() > MAX_MODEL_RESOURCES {
        risk_notes.push(format!(
            "Model resource list truncated to first {MAX_MODEL_RESOURCES} entries ({} total models visible)",
            models.len()
        ));
    }

    if resources.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "account".into(),
            name: "anthropic_api_key".into(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Anthropic account associated with this API key".to_string(),
        });
        risk_notes.push("No models were enumerable for this key".to_string());
    }

    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = Severity::Low;

    Ok(AccessMapResult {
        cloud: "anthropic".into(),
        identity: AccessSummary {
            id: "anthropic_api_key".into(),
            access_type: "token".into(),
            project: None,
            tenant: None,
            account_id: None,
        },
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: None,
            username: None,
            account_type: Some("api_key".into()),
            company: None,
            location: None,
            email: None,
            url: Some("https://console.anthropic.com/settings/keys".into()),
            token_type: Some(token_kind.to_string()),
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: None,
            scopes: Vec::new(),
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn list_models(client: &Client, token: &str) -> Result<Vec<AnthropicModel>> {
    let resp = client
        .get(format!("{ANTHROPIC_API}/models"))
        .header("x-api-key", token)
        .header("anthropic-version", ANTHROPIC_VERSION)
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("Anthropic access-map: failed to list models")?;

    if !resp.status().is_success() {
        return Err(anyhow!(
            "Anthropic access-map: model listing failed with HTTP {}",
            resp.status()
        ));
    }

    let body: AnthropicModelsResponse =
        resp.json().await.context("Anthropic access-map: invalid model list JSON")?;
    Ok(body.data)
}

fn detect_token_type(token: &str) -> &'static str {
    if token.starts_with("sk-ant-admin") {
        "admin_api_key"
    } else if token.starts_with("sk-ant-api") {
        "api_key"
    } else {
        "unknown_api_key"
    }
}

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
