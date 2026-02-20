use std::collections::BTreeSet;

use anyhow::{anyhow, Context, Result};
use reqwest::{header, Client, StatusCode};
use serde::Deserialize;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    build_recommendations, AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary,
    ResourceExposure, RoleBinding, Severity,
};

const OPENAI_API: &str = "https://api.openai.com/v1";
const MAX_MODEL_RESOURCES: usize = 50;

#[derive(Debug, Deserialize, Default, Clone)]
struct OpenAiMe {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    email: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct OpenAiModelsResponse {
    #[serde(default)]
    data: Vec<OpenAiModel>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct OpenAiModel {
    #[serde(default)]
    id: Option<String>,
    #[serde(default, rename = "owned_by")]
    owned_by: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct OpenAiProjectsResponse {
    #[serde(default)]
    data: Vec<OpenAiProject>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct OpenAiProject {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    archived: bool,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read OpenAI token from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!("OpenAI access-map requires a validated token from scan results"));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build OpenAI HTTP client")?;

    let mut risk_notes = Vec::new();
    let mut roles = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut resources = Vec::new();

    let models_result = list_models(&client, token).await;
    let me_result = fetch_me(&client, token).await;
    if models_result.is_err() && me_result.is_err() {
        return Err(anyhow!(
            "OpenAI access-map: both /models and /me lookups failed; token may not be valid for access mapping"
        ));
    }

    let models = models_result.unwrap_or_else(|err| {
        warn!("OpenAI access-map: model enumeration failed: {err}");
        risk_notes.push(format!("Model enumeration failed: {err}"));
        Vec::new()
    });
    let me = me_result.unwrap_or_else(|err| {
        warn!("OpenAI access-map: /me lookup failed: {err}");
        risk_notes.push(format!("Identity lookup failed: {err}"));
        OpenAiMe::default()
    });

    let token_kind = detect_token_type(token);
    roles.push(RoleBinding {
        name: format!("token_type:{token_kind}"),
        source: "openai".into(),
        permissions: vec![format!("token:{token_kind}")],
    });

    permissions.read_only.push("models:list".to_string());

    let projects = list_projects(&client, token).await.unwrap_or_else(|err| {
        warn!("OpenAI access-map: project enumeration failed: {err}");
        risk_notes.push(format!("Project enumeration failed: {err}"));
        Vec::new()
    });

    if !projects.is_empty() {
        permissions.risky.push("projects:list".to_string());
    }

    let identity_id = me
        .email
        .clone()
        .or_else(|| me.name.clone())
        .or_else(|| me.id.clone())
        .unwrap_or_else(|| "openai_api_key".to_string());

    let mut owners = BTreeSet::new();
    for model in &models {
        if let Some(owner) = model.owned_by.as_ref() {
            if !owner.is_empty() {
                owners.insert(owner.clone());
            }
        }
    }

    for owner in owners {
        resources.push(ResourceExposure {
            resource_type: "organization".into(),
            name: owner,
            permissions: vec!["models:list".to_string()],
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "Organization inferred from accessible models".to_string(),
        });
    }

    for project in &projects {
        let project_name = project
            .name
            .clone()
            .or_else(|| project.id.clone())
            .unwrap_or_else(|| "unknown_project".to_string());
        let risk = if project.archived { Severity::Low } else { Severity::Medium };
        resources.push(ResourceExposure {
            resource_type: "project".into(),
            name: project_name,
            permissions: vec!["project:read".to_string()],
            risk: severity_to_str(risk).to_string(),
            reason: "Project visible to this OpenAI key".to_string(),
        });
    }

    let mut model_count = 0usize;
    for model in &models {
        if model_count >= MAX_MODEL_RESOURCES {
            break;
        }
        if let Some(model_id) = model.id.as_ref() {
            resources.push(ResourceExposure {
                resource_type: "model".into(),
                name: model_id.clone(),
                permissions: vec!["model:read".to_string()],
                risk: severity_to_str(Severity::Low).to_string(),
                reason: "Model accessible to this OpenAI key".to_string(),
            });
            model_count += 1;
        }
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
            name: identity_id.clone(),
            permissions: Vec::new(),
            risk: severity_to_str(Severity::Low).to_string(),
            reason: "OpenAI account associated with this API key".to_string(),
        });
        risk_notes.push("No projects, organizations, or models were enumerable".to_string());
    }

    permissions.admin.sort();
    permissions.admin.dedup();
    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();

    let severity = derive_severity(&permissions, projects.len(), models.len());

    Ok(AccessMapResult {
        cloud: "openai".into(),
        identity: AccessSummary {
            id: identity_id,
            access_type: "token".into(),
            project: None,
            tenant: None,
            account_id: me.id.clone(),
        },
        roles,
        permissions,
        resources,
        severity,
        recommendations: build_recommendations(severity),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: me.name,
            username: None,
            account_type: Some("api_key".into()),
            company: None,
            location: None,
            email: me.email,
            url: Some("https://platform.openai.com/".into()),
            token_type: Some(token_kind.to_string()),
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: me.id,
            scopes: Vec::new(),
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn list_models(client: &Client, token: &str) -> Result<Vec<OpenAiModel>> {
    let resp = client
        .get(format!("{OPENAI_API}/models"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("OpenAI access-map: failed to list models")?;

    if !resp.status().is_success() {
        return Err(anyhow!("OpenAI access-map: model listing failed with HTTP {}", resp.status()));
    }

    let body: OpenAiModelsResponse =
        resp.json().await.context("OpenAI access-map: invalid model list JSON")?;
    Ok(body.data)
}

async fn fetch_me(client: &Client, token: &str) -> Result<OpenAiMe> {
    let resp = client
        .get(format!("{OPENAI_API}/me"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("OpenAI access-map: failed to query /me")?;

    if !resp.status().is_success() {
        return Err(anyhow!("OpenAI access-map: /me failed with HTTP {}", resp.status()));
    }

    resp.json().await.context("OpenAI access-map: invalid /me JSON")
}

async fn list_projects(client: &Client, token: &str) -> Result<Vec<OpenAiProject>> {
    let resp = client
        .get(format!("{OPENAI_API}/organization/projects"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::ACCEPT, "application/json")
        .send()
        .await
        .context("OpenAI access-map: failed to list organization projects")?;

    match resp.status() {
        StatusCode::OK => {
            let body: OpenAiProjectsResponse =
                resp.json().await.context("OpenAI access-map: invalid projects JSON")?;
            Ok(body.data)
        }
        StatusCode::FORBIDDEN | StatusCode::NOT_FOUND => Ok(Vec::new()),
        StatusCode::UNAUTHORIZED => {
            Err(anyhow!("OpenAI access-map: project listing unauthorized (401)"))
        }
        status => Err(anyhow!("OpenAI access-map: project listing failed with HTTP {status}")),
    }
}

fn detect_token_type(token: &str) -> &'static str {
    if token.starts_with("sk-proj-") {
        "project_api_key"
    } else if token.starts_with("sk-svcacct-") {
        "service_account_api_key"
    } else if token.starts_with("sk-None-") {
        "legacy_api_key"
    } else {
        "api_key"
    }
}

fn derive_severity(permissions: &PermissionSummary, projects: usize, models: usize) -> Severity {
    if !permissions.admin.is_empty() {
        return Severity::High;
    }
    if !permissions.risky.is_empty() || projects > 0 {
        return Severity::Medium;
    }
    if models > 0 {
        return Severity::Low;
    }
    Severity::Low
}

fn severity_to_str(severity: Severity) -> &'static str {
    match severity {
        Severity::Low => "low",
        Severity::Medium => "medium",
        Severity::High => "high",
        Severity::Critical => "critical",
    }
}
