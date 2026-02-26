//! Unkey root key access mapping.
//!
//! Maps Unkey root keys to the API namespaces and workspace resources they can access.
//! Only root keys (unkey_xxx) are supported—end-user API keys cannot be mapped without a root key.

use anyhow::{anyhow, Context, Result};
use reqwest::{header, Client, StatusCode};
use serde::Deserialize;
use tracing::warn;

use crate::{cli::commands::access_map::AccessMapArgs, validation::GLOBAL_USER_AGENT};

use super::{
    build_recommendations, AccessMapResult, AccessSummary, AccessTokenDetails, PermissionSummary,
    ResourceExposure, RoleBinding, Severity,
};

const UNKEY_API: &str = "https://api.unkey.com/v2";
const MAX_PERMISSIONS: usize = 50;
const MAX_IDENTITIES: usize = 20;
const MAX_KEYS_PER_API: usize = 10;

#[derive(Debug, Deserialize, Default, Clone)]
struct UnkeyListApisResponse {
    #[serde(default)]
    #[allow(dead_code)]
    meta: UnkeyMeta,
    #[serde(default)]
    data: Vec<UnkeyApi>,
    #[serde(default)]
    pagination: UnkeyPagination,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct UnkeyMeta {
    #[serde(default, alias = "requestId")]
    #[allow(dead_code)]
    request_id: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct UnkeyApi {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct UnkeyPagination {
    #[serde(default, alias = "hasMore")]
    has_more: Option<bool>,
    #[serde(default)]
    cursor: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct UnkeyPermission {
    #[serde(default)]
    id: Option<String>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    slug: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct UnkeyListPermissionsResponse {
    #[serde(default)]
    data: Vec<UnkeyPermission>,
    #[serde(default)]
    #[allow(dead_code)]
    pagination: UnkeyPagination,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct UnkeyIdentity {
    #[serde(default)]
    #[allow(dead_code)]
    id: Option<String>,
    #[serde(default, alias = "externalId")]
    #[allow(dead_code)]
    external_id: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct UnkeyListIdentitiesResponse {
    #[serde(default)]
    data: Option<Vec<UnkeyIdentity>>,
    #[serde(default)]
    #[allow(dead_code)]
    pagination: UnkeyPagination,
}

#[derive(Debug, Deserialize, Default, Clone)]
struct UnkeyListKeysResponse {
    #[serde(default)]
    data: Vec<serde_json::Value>,
    #[serde(default)]
    #[allow(dead_code)]
    pagination: UnkeyPagination,
}

pub async fn map_access(args: &AccessMapArgs) -> Result<AccessMapResult> {
    let token = if let Some(path) = args.credential_path.as_deref() {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read Unkey root key from {}", path.display()))?;
        raw.trim().to_string()
    } else {
        return Err(anyhow!(
            "Unkey access-map requires a validated root key from scan results"
        ));
    };

    map_access_from_token(&token).await
}

pub async fn map_access_from_token(token: &str) -> Result<AccessMapResult> {
    let client = Client::builder()
        .user_agent(GLOBAL_USER_AGENT.as_str())
        .build()
        .context("Failed to build Unkey HTTP client")?;

    let mut risk_notes = Vec::new();
    let mut roles = Vec::new();
    let mut permissions = PermissionSummary::default();
    let mut resources = Vec::new();
    let mut scopes = Vec::new();

    roles.push(RoleBinding {
        name: "root_key".to_string(),
        source: "unkey".into(),
        permissions: vec!["unkey:root_key".to_string()],
    });

    permissions.risky.push("workspace:manage".to_string());

    // 1. List API namespaces (requires api.*.read_api)
    let apis = list_apis(&client, token).await.unwrap_or_else(|err| {
        warn!("Unkey access-map: apis.list failed: {err}");
        risk_notes.push(format!("API namespace enumeration failed: {err}"));
        Vec::new()
    });

    if !apis.is_empty() {
        permissions.read_only.push("apis:list".to_string());
        scopes.push("api.*.read_api".to_string());
    }

    for api in &apis {
        let api_id = api.id.as_deref().unwrap_or("unknown");
        let api_name = api.name.as_deref().unwrap_or(api_id);
        let key_count = list_keys_count(&client, token, api_id).await.unwrap_or(0);
        let key_label = if key_count > 0 {
            format!("{} — {api_name} ({key_count} keys)", api_id)
        } else {
            format!("{} — {api_name}", api_id)
        };
        resources.push(ResourceExposure {
            resource_type: "api_namespace".into(),
            name: key_label,
            permissions: vec![
                "api:read".to_string(),
                "keys:create".to_string(),
                "keys:verify".to_string(),
                "keys:delete".to_string(),
            ],
            risk: "high".to_string(),
            reason: "API namespace accessible to this root key; can create, verify, and delete keys"
                .to_string(),
        });
    }

    // 2. List workspace permissions (requires rbac.*.read_permission)
    let workspace_perms = list_permissions(&client, token).await.unwrap_or_else(|err| {
        warn!("Unkey access-map: permissions.listPermissions failed: {err}");
        Vec::new()
    });

    if !workspace_perms.is_empty() {
        permissions.read_only.push("rbac:read_permissions".to_string());
        scopes.push("rbac.*.read_permission".to_string());
        risk_notes.push(format!(
            "Root key can read {} workspace permission definition(s)",
            workspace_perms.len()
        ));
        for perm in workspace_perms.iter().take(MAX_PERMISSIONS) {
            let perm_slug = perm
                .slug
                .as_deref()
                .or(perm.name.as_deref())
                .or(perm.id.as_deref())
                .unwrap_or("unknown");
            scopes.push(perm_slug.to_string());
            permissions.risky.push(format!("workspace_perm:{perm_slug}"));
        }
        if workspace_perms.len() > MAX_PERMISSIONS {
            resources.push(ResourceExposure {
                resource_type: "permission".into(),
                name: format!(
                    "{} permission definitions (showing first {MAX_PERMISSIONS})",
                    workspace_perms.len()
                ),
                permissions: vec!["rbac:read_permission".to_string()],
                risk: "medium".to_string(),
                reason: "Workspace permission definitions visible to this root key".to_string(),
            });
        } else {
            for perm in &workspace_perms {
                let perm_name = perm
                    .name
                    .as_deref()
                    .or(perm.slug.as_deref())
                    .or(perm.id.as_deref())
                    .unwrap_or("unknown");
                resources.push(ResourceExposure {
                    resource_type: "permission".into(),
                    name: perm_name.to_string(),
                    permissions: vec!["rbac:read_permission".to_string()],
                    risk: "medium".to_string(),
                    reason: "Workspace permission definition visible to this root key".to_string(),
                });
            }
        }
    }

    // 3. List identities (requires identity.*.read_identity)
    let identity_count = list_identities_count(&client, token).await.unwrap_or(0);
    if identity_count > 0 {
        scopes.push("identity.*.read_identity".to_string());
        permissions.read_only.push("identities:list".to_string());
        let label = if identity_count >= MAX_IDENTITIES {
            format!("≥{identity_count} identity(ies) in workspace")
        } else {
            format!("{identity_count} identity(ies) in workspace")
        };
        resources.push(ResourceExposure {
            resource_type: "identity".into(),
            name: label,
            permissions: vec!["identity:read".to_string()],
            risk: "medium".to_string(),
            reason: "Identity list accessible; root key can read identity metadata and rate limits"
                .to_string(),
        });
    }

    if resources.is_empty() {
        resources.push(ResourceExposure {
            resource_type: "workspace".into(),
            name: "unkey_workspace".into(),
            permissions: vec!["root_key".to_string()],
            risk: "high".to_string(),
            reason: "Unkey workspace—root key has administrative access".to_string(),
        });
    }

    permissions.risky.sort();
    permissions.risky.dedup();
    permissions.read_only.sort();
    permissions.read_only.dedup();
    scopes.sort();
    scopes.dedup();
    if scopes.is_empty() {
        scopes.push("workspace:full".to_string());
    }

    Ok(AccessMapResult {
        cloud: "unkey".into(),
        identity: AccessSummary {
            id: "unkey_root_key".into(),
            access_type: "root_key".into(),
            project: None,
            tenant: None,
            account_id: None,
        },
        roles,
        permissions,
        resources,
        severity: Severity::High,
        recommendations: build_recommendations(Severity::High),
        risk_notes,
        token_details: Some(AccessTokenDetails {
            name: None,
            username: None,
            account_type: Some("root_key".into()),
            company: None,
            location: None,
            email: None,
            url: Some("https://app.unkey.com/settings/root-keys".into()),
            token_type: Some("root_key".into()),
            created_at: None,
            last_used_at: None,
            expires_at: None,
            user_id: None,
            scopes,
        }),
        provider_metadata: None,
        fingerprint: None,
    })
}

async fn list_apis(client: &Client, token: &str) -> Result<Vec<UnkeyApi>> {
    let mut all_apis = Vec::new();
    let mut cursor: Option<String> = None;

    loop {
        let body = match &cursor {
            Some(c) => serde_json::json!({ "cursor": c }),
            None => serde_json::json!({}),
        };

        let resp = client
            .post(format!("{UNKEY_API}/apis.list"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .json(&body)
            .send()
            .await
            .context("Unkey access-map: failed to list APIs")?;

        if !resp.status().is_success() {
            return Err(anyhow!(
                "Unkey access-map: apis.list failed with HTTP {}",
                resp.status()
            ));
        }

        let envelope: UnkeyListApisResponse = resp
            .json()
            .await
            .context("Unkey access-map: invalid apis.list JSON")?;

        all_apis.extend(envelope.data);

        if envelope.pagination.has_more.unwrap_or(false) {
            cursor = envelope.pagination.cursor;
            if cursor.is_none() {
                break;
            }
        } else {
            break;
        }
    }

    Ok(all_apis)
}

async fn list_permissions(client: &Client, token: &str) -> Result<Vec<UnkeyPermission>> {
    let mut all = Vec::new();
    let mut cursor: Option<String> = None;

    loop {
        let body = match &cursor {
            Some(c) => serde_json::json!({ "cursor": c, "limit": 50 }),
            None => serde_json::json!({ "limit": 50 }),
        };

        let resp = client
            .post(format!("{UNKEY_API}/permissions.listPermissions"))
            .header(header::AUTHORIZATION, format!("Bearer {token}"))
            .header(header::CONTENT_TYPE, "application/json")
            .header(header::ACCEPT, "application/json")
            .json(&body)
            .send()
            .await
            .context("Unkey access-map: failed to list permissions")?;

        if resp.status() == StatusCode::FORBIDDEN {
            return Err(anyhow!(
                "Root key lacks rbac.*.read_permission (403 Forbidden)"
            ));
        }
        if !resp.status().is_success() {
            return Err(anyhow!(
                "Unkey access-map: permissions.listPermissions failed with HTTP {}",
                resp.status()
            ));
        }

        let envelope: UnkeyListPermissionsResponse = resp
            .json()
            .await
            .context("Unkey access-map: invalid permissions JSON")?;

        all.extend(envelope.data);

        if envelope.pagination.has_more.unwrap_or(false) {
            cursor = envelope.pagination.cursor;
            if cursor.is_none() {
                break;
            }
        } else {
            break;
        }
    }
    Ok(all)
}

async fn list_identities_count(client: &Client, token: &str) -> Result<usize> {
    let body = serde_json::json!({ "limit": MAX_IDENTITIES });
    let resp = client
        .post(format!("{UNKEY_API}/identities.listIdentities"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .json(&body)
        .send()
        .await
        .context("Unkey access-map: failed to list identities")?;

    if resp.status() == StatusCode::FORBIDDEN {
        return Ok(0);
    }
    if !resp.status().is_success() {
        return Err(anyhow!(
            "Unkey access-map: identities.listIdentities failed with HTTP {}",
            resp.status()
        ));
    }

    let envelope: UnkeyListIdentitiesResponse = resp
        .json()
        .await
        .context("Unkey access-map: invalid identities JSON")?;

    let count = envelope.data.as_deref().map(|v| v.len()).unwrap_or(0);
    Ok(count)
}

async fn list_keys_count(client: &Client, token: &str, api_id: &str) -> Result<usize> {
    let body = serde_json::json!({
        "apiId": api_id,
        "limit": MAX_KEYS_PER_API
    });
    let resp = client
        .post(format!("{UNKEY_API}/apis.listKeys"))
        .header(header::AUTHORIZATION, format!("Bearer {token}"))
        .header(header::CONTENT_TYPE, "application/json")
        .header(header::ACCEPT, "application/json")
        .json(&body)
        .send()
        .await
        .context("Unkey access-map: failed to list keys")?;

    if resp.status() == StatusCode::FORBIDDEN || resp.status() == StatusCode::NOT_FOUND {
        return Ok(0);
    }
    if !resp.status().is_success() {
        return Err(anyhow!(
            "Unkey access-map: apis.listKeys failed with HTTP {}",
            resp.status()
        ));
    }

    let envelope: UnkeyListKeysResponse = resp
        .json()
        .await
        .context("Unkey access-map: invalid listKeys JSON")?;

    Ok(envelope.data.len())
}
