# Kingfisher

<p align="center">
  <img src="docs/kingfisher_logo.png" alt="Kingfisher Logo" width="126" height="173" style="vertical-align: right;" />

[![License](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)<br>
[![ghcr downloads](https://ghcr-badge.elias.eu.org/shield/mongodb/kingfisher/kingfisher)](https://github.com/mongodb/kingfisher/pkgs/container/kingfisher)<br>


Kingfisher is a blazingly fast secret-scanning and **live validation** tool built in Rust.

It combines Intel's SIMD-accelerated regex engine (Hyperscan) with language-aware parsing to achieve high accuracy at massive scale, and **ships with hundreds of built-in rules** to detect, **validate**, and triage secrets before they ever reach production.  

Designed for offensive security engineers and blue-teamers alike, Kingfisher helps you pivot across repo ecosystems, validate exposure paths, and hunt for developer-owned leaks that spill beyond the primary codebase.

</p>

**Learn more:** [Introducing Kingfisher: Real‑Time Secret Detection and Validation](https://www.mongodb.com/blog/post/product-release-announcements/introducing-kingfisher-real-time-secret-detection-validation)

## Key Features

### Multiple Scan Targets
<div align="center">

| Files / Dirs | Local Git | GitHub | GitLab | Azure Repos | Bitbucket | Gitea | Hugging Face |
|:-------------:|:----------:|:------:|:------:|:-------------:|:----------:|:------:|:-------------:|
| <img src="./docs/assets/icons/files.svg" height="40" alt="Files / Dirs"/><br/><sub>Files / Dirs</sub> | <img src="./docs/assets/icons/local-git.svg" height="40" alt="Local Git"/><br/><sub>Local Git</sub> | <img src="./docs/assets/icons/github.svg" height="40" alt="GitHub"/><br/><sub>GitHub</sub> | <img src="./docs/assets/icons/gitlab.svg" height="40" alt="GitLab"/><br/><sub>GitLab</sub> | <img src="./docs/assets/icons/azure-devops.svg" height="40" alt="Azure Repos"/><br/><sub>Azure Repos</sub> | <img src="./docs/assets/icons/bitbucket.svg" height="40" alt="Bitbucket"/><br/><sub>Bitbucket</sub> | <img src="./docs/assets/icons/gitea.svg" height="40" alt="Gitea"/><br/><sub>Gitea</sub> |<img src="./docs/assets/icons/huggingface.svg" height="40" width="40" alt="Hugging Face"/><br/><sub>Hugging Face</sub> |

| Docker | Jira | Confluence | Slack | AWS S3 | Google Cloud |
|:------:|:----:|:-----------:|:-----:|:------:|:---:|
| <img src="./docs/assets/icons/docker.svg" height="40" alt="Docker"/><br/><sub>Docker</sub> | <img src="./docs/assets/icons/jira.svg" height="40" alt="Jira"/><br/><sub>Jira</sub> | <img src="./docs/assets/icons/confluence.svg" height="40" alt="Confluence"/><br/><sub>Confluence</sub> | <img src="./docs/assets/icons/slack.svg" height="40" alt="Slack"/><br/><sub>Slack</sub> | <img src="./docs/assets/icons/aws-s3.svg" height="40" alt="AWS S3"/><br/><sub>AWS&nbsp;S3</sub> |  <img src="./docs/assets/icons/gcs.svg" height="40" alt="Google Cloud Storage"/><br/><sub>Cloud Storage</sub> |

</div>

### Performance, Accuracy, and Hundreds of Rules
- **Performance**: multithreaded, Hyperscan‑powered scanning built for huge codebases  
- **Extensible rules**: hundreds of built-in detectors plus YAML-defined custom rules ([docs/RULES.md](/docs/RULES.md))  
- **Blast Radius Mapping**: instantly map leaked keys to their effective cloud identities and exposed resources with `--access-map`. Supports AWS, GCP, Azure, GitHub, Gitlab, and more token support coming.
- **Broad AI SaaS coverage**: finds and validates tokens for OpenAI, Anthropic, Google Gemini, Cohere, AWS Bedrock, Voyage AI, Mistral, Stability AI, Replicate, xAI (Grok), Ollama, Langchain, Perplexity, Weights & Biases, Cerebras, Friendli, Fireworks.ai, NVIDIA NIM, Together.ai, Zhipu, and many more
- **Compressed Files**: Supports extracting and scanning compressed files for secrets
- **Baseline management**: generate and track baselines to suppress known secrets ([docs/BASELINE.md](/docs/BASELINE.md))
- **Checksum-aware detection**: verifies tokens with built-in checksums (e.g., GitHub, Confluent, Zuplo) — no API calls required
- **Built-in Report Viewer**: Visualize and triage findings locally with `kingisher view ./report-file.json`
- **Library crates**: Embed Kingfisher's scanning engine in your own Rust applications ([docs/LIBRARY.md](docs/LIBRARY.md))

# Benchmark Results

See ([docs/COMPARISON.md](docs/COMPARISON.md))

<p align="center">
  <img src="docs/runtime-comparison.png" alt="Kingfisher Runtime Comparison" style="vertical-align: center;" />
</p>

## Basic Usage Demo
```bash
kingfisher scan /path/to/scan --view-report
```
NOTE: Replay has been slowed down for demo
![alt text](docs/kingfisher-usage-01.gif)

## Report Viewer Demo
Explore Kingfisher's built-in report viewer and its `--access-map`, which can show what the token (AWS, GCP, Azure, GitHub, GitLab, and Slack...more coming) can actually access.

Note: when you pass `--view-report`, Kingfisher starts a **localhost-only** web server on port `7890` and opens it in your default browser. You'll see this near the end of the scan output, and **Kingfisher will keep running** until you stop it.

```bash
INFO kingfisher::cli::commands::view: Starting access-map viewer address=127.0.0.1:7890
Serving access-map viewer at http://127.0.0.1:7890 (Ctrl+C to stop)
```

**Usage:**
```bash
kingfisher scan /path/to/scan --access-map --view-report
```

![alt text](docs/kingfisher-usage-access-map-01.gif)

**Click to view video**
[![Demo](docs/demos/findings-thumbnail.png)](https://github.com/user-attachments/assets/d33ee7a6-c60a-4e42-88e0-ac03cb429a46)

# Table of Contents

- [Key Features](#key-features)
- [Benchmark Results](#benchmark-results)
- [Getting Started](#getting-started)
  - [Quick Start](#quick-start)
  - [Installation](#installation)
- [Detection Rules](#detection-rules)
- [Usage Examples](#usage-examples)
- [Platform Integrations](#platform-integrations)
- [Advanced Features](#advanced-features)
- [Documentation](#documentation)
- [Library Usage](#library-usage)
- [Roadmap](#roadmap)
- [License](#license)

# Getting Started

## Quick Start

```bash
# Install via Homebrew
brew install kingfisher

# Or use the install script (Linux/macOS)
curl --silent --location \
  https://raw.githubusercontent.com/mongodb/kingfisher/main/scripts/install-kingfisher.sh | bash

# Scan a directory
kingfisher scan /path/to/code

# View results in browser
kingfisher scan /path/to/code --view-report
```

## Installation

Kingfisher supports multiple installation methods:

- **Homebrew**: `brew install kingfisher` ![Homebrew Formula Version](https://img.shields.io/homebrew/v/kingfisher)
- **Pre-built releases**: Download from [GitHub Releases](https://github.com/mongodb/kingfisher/releases)
- **Install scripts**: One-line installers for Linux, macOS, and Windows
- **Docker**: `docker run ghcr.io/mongodb/kingfisher:latest`
- **Pre-commit hooks**: Integrate with git hooks, pre-commit framework, or Husky
- **Compile from source**: Build with `make` for your platform

**For complete installation instructions and pre-commit hook setup, see [docs/INSTALLATION.md](docs/INSTALLATION.md).**

# Detection Rules

Kingfisher ships with [hundreds of rules](crates/kingfisher-rules/data/rules/) that cover everything from classic cloud keys to the latest AI SaaS tokens. Below is an overview:

| Category | What we catch |
|----------|---------------|
| **AI SaaS APIs** | OpenAI, Anthropic, Google Gemini, Cohere, Mistral, Stability AI, Replicate, xAI (Grok), Ollama, Langchain, Perplexity, Weights & Biases, Cerebras, Friendli, Fireworks.ai, NVIDIA NIM, together.ai, Zhipu, and more |
| **Cloud Providers** | AWS, Azure, GCP, Alibaba Cloud, DigitalOcean, IBM Cloud, Cloudflare, and more |
| **Dev & CI/CD** | GitHub/GitLab tokens, CircleCI, TravisCI, TeamCity, Docker Hub, npm, PyPI, and more |
| **Messaging & Comms** | Slack, Discord, Microsoft Teams, Twilio, Mailgun, SendGrid, Mailchimp, and more |
| **Databases & Data Ops** | MongoDB Atlas, PlanetScale, Postgres DSNs, Grafana Cloud, Datadog, Dynatrace, and more |
| **Payments & Billing** | Stripe, PayPal, Square, GoCardless, and more |
| **Security & DevSecOps** | Snyk, Dependency-Track, CodeClimate, Codacy, OpsGenie, PagerDuty, and more |
| **Misc. SaaS & Tools** | 1Password, Adobe, Atlassian/Jira, Asana, Netlify, Baremetrics, and more |

## Write Custom Rules

Kingfisher ships with hundreds of rules with HTTP and service‑specific validation checks (AWS, Azure, GCP, etc.) to confirm if a detected string is a live credential.

However, you may want to add your own custom rules, or modify a detection to better suit your needs / environment.

**For complete rule documentation, see [docs/RULES.md](docs/RULES.md).**

### Checksum Intelligence

Modern API tokens increasingly include **built-in checksums**, short internal digests that make each credential self-verifiable. (For background, see [GitHub's write-up on their newer token formats](https://github.blog/engineering/platform-security/behind-githubs-new-authentication-token-formats/) and why checksums slash false positives.)

Kingfisher supports **checksum-aware matching** in rules, enabling **offline structural verification** of credentials *without* calling third-party APIs.

By validating each token's internal checksum (for tokens that support checksums), Kingfisher eliminates nearly all false positives—automatically skipping structurally invalid or fake tokens before validation ever runs.

**Why this matters**
- **Offline verification** — no API call required  
- **Industry-aligned** — compatible with prefix + checksum token designs (e.g., modern PATs)  
- **Lower false positives** — invalid tokens are filtered out by structure alone

**Learn more**: implementation details and templating are documented in **[docs/RULES.md](docs/RULES.md)**

# Usage Examples

> **Note**: `kingfisher scan` automatically detects whether the input is a Git repository or a plain directory—no extra flags required.

## Basic Scanning

```bash
# Scan with secret validation
kingfisher scan /path/to/code
## NOTE: This path can refer to:
# 1. a local git repo
# 2. a directory with many git repos
# 3. or just a folder with files and subdirectories

# Scan without validation
kingfisher scan ~/src/myrepo --no-validate

# Display only secrets confirmed active by third‑party APIs
kingfisher scan /path/to/repo --only-valid

# Output JSON and capture to a file
kingfisher scan . --format json | tee kingfisher.json

# Output SARIF directly to disk
kingfisher scan /path/to/repo --format sarif --output findings.sarif
```

## Access Map and Visualization

**Stop Guessing, Start Mapping: Understand Your True Blast Radius**

Finding a leaked credential is only the first step. The critical question isn't just "Is this a secret?"—it's "What can an attacker do with it?"

Kingfisher's `--access-map` feature transforms secret detection from a simple alert into a comprehensive threat assessment. Instead of leaving you with a cryptic API key, Kingfisher actively authenticates against your cloud provider (AWS, GCP, Azure Storage, Azure DevOps, GitHub, GitLab, or Slack) to map the full extent of the credential's power. 

* Instant Identity Resolution: Immediately identify who the key belongs to—whether it's a specific IAM user, an assumed role, or a service account.
* Visualize the Blast Radius: See exactly which resources (S3 buckets, EC2 instances, projects, storage containers) are exposed and at risk.

```bash
# Generate access map during scan
kingfisher scan /path/to/code --access-map --view-report

# View access-map reports locally
kingfisher view kingfisher.json
```

> **Use the access map functionality only when you are authorized to inspect the target account, as Kingfisher will issue additional network requests to determine what access the secret grants**

## Direct Secret Validation & Revocation

```bash
# Validate a known secret without scanning
kingfisher validate --rule opsgenie "12345678-9abc-def0-1234-56789abcdef0"

# Validate from stdin
echo "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx" | kingfisher validate --rule github -

# Revoke a Slack token
kingfisher revoke --rule slack "xoxb-..."

# Revoke a GitHub PAT
kingfisher revoke --rule github "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
```

## Advanced Scanning Options

```bash
# Pipe any text directly into Kingfisher
cat /path/to/file.py | kingfisher scan -

# Limit maximum file size scanned (default: 256 MB)
kingfisher scan /some/file --max-file-size 500

# Scan using a rule family
kingfisher scan /path/to/repo --rule kingfisher.aws

# Display rule performance statistics
kingfisher scan /path/to/repo --rule-stats

# Exclude specific paths
kingfisher scan ./my-project \
  --exclude '*.py' \
  --exclude '[Tt]ests'

# Scan changes in CI pipelines
kingfisher scan . \
  --since-commit origin/main \
  --branch "$CI_BRANCH"
```

# Platform Integrations

Kingfisher can scan multiple platforms and services directly. See **[docs/INTEGRATIONS.md](docs/INTEGRATIONS.md)** for complete integration documentation.

## Quick Examples

```bash
# Scan AWS S3 bucket
kingfisher scan s3 bucket-name --prefix path/

# Scan Google Cloud Storage
kingfisher scan gcs bucket-name

# Scan Docker image
kingfisher scan docker ghcr.io/owasp/wrongsecrets/wrongsecrets-master:latest-master

# Scan GitHub organization
kingfisher scan github --organization my-org

# Scan GitLab group
kingfisher scan gitlab --group my-group

# Scan Azure Repos
kingfisher scan azure --organization my-org

# Scan Jira issues
KF_JIRA_TOKEN="token" kingfisher scan jira --url https://jira.company.com \
  --jql "project = TEST AND status = Open"

# Scan Confluence pages
KF_CONFLUENCE_TOKEN="token" kingfisher scan confluence --url https://confluence.company.com \
  --cql "label = secret"

# Scan Slack messages
KF_SLACK_TOKEN="xoxp-..." kingfisher scan slack "from:username has:link"
```

**For detailed integration instructions and authentication setup, see [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md).**

# Advanced Features

Kingfisher offers powerful features for complex scanning scenarios. See **[docs/ADVANCED.md](docs/ADVANCED.md)** for complete advanced documentation.

## Baseline Management

Track known secrets and detect only new ones:

```bash
# Create/update baseline
kingfisher scan /path/to/code \
  --confidence low \
  --manage-baseline \
  --baseline-file ./baseline-file.yml

# Scan with baseline (suppress known findings)
kingfisher scan /path/to/code \
  --baseline-file /path/to/baseline-file.yaml
```

## Filtering and Suppression

```bash
# Skip known false positives
kingfisher scan --skip-regex '(?i)TEST_KEY' path/
kingfisher scan --skip-word dummy path/

# Skip AWS canary tokens
kingfisher scan /path/to/code \
  --skip-aws-account "171436882533,534261010715"

# Inline ignore directives in code
# Add `kingfisher:ignore` on the same line or surrounding lines
```

## CI Pipeline Scanning

```bash
# Scan only changes between branches
kingfisher scan . \
  --since-commit origin/main \
  --branch "$CI_BRANCH"

# Scan specific commit range
kingfisher scan /tmp/repo --branch feature-1 \
  --branch-root-commit $(git -C /tmp/repo merge-base main feature-1)
```

**For more advanced features including confidence levels, validation tuning, and custom rules, see [docs/ADVANCED.md](docs/ADVANCED.md).**

# Documentation

| Document | Description |
|----------|-------------|
| [INSTALLATION.md](docs/INSTALLATION.md) | Complete installation guide including pre-commit hooks setup for git, pre-commit framework, and Husky |
| [INTEGRATIONS.md](docs/INTEGRATIONS.md) | Platform-specific scanning guide (GitHub, GitLab, AWS S3, Docker, Jira, Confluence, Slack, etc.) |
| [ADVANCED.md](docs/ADVANCED.md) | Advanced features: baselines, confidence levels, validation tuning, CI scanning, and more |
| [RULES.md](docs/RULES.md) | Writing custom detection rules, pattern requirements, and checksum intelligence |
| [BASELINE.md](docs/BASELINE.md) | Baseline management for tracking known secrets and detecting new ones |
| [LIBRARY.md](docs/LIBRARY.md) | Using Kingfisher as a Rust library in your own applications |
| [FINGERPRINT.md](docs/FINGERPRINT.md) | Understanding finding fingerprints and deduplication |
| [COMPARISON.md](docs/COMPARISON.md) | Benchmark results and performance comparisons |
| [PARSING.md](docs/PARSING.md) | Language-aware parsing details |

# Library Usage

Kingfisher's scanning engine is available as a set of Rust library crates that can be embedded into other applications:

| Crate | Description |
|-------|-------------|
| `kingfisher-core` | Core types: `Blob`, `BlobId`, `Location`, `Origin`, entropy calculation |
| `kingfisher-rules` | Rule definitions, YAML parsing, compiled rule database, 200+ builtin rules |
| `kingfisher-scanner` | High-level scanning API with `Scanner` and `Finding` types |

**Quick example:**

```rust
use std::sync::Arc;
use kingfisher_rules::{get_builtin_rules, RulesDatabase, Rule};
use kingfisher_scanner::Scanner;

// Load builtin rules and compile
let rules = get_builtin_rules(None)?;
let rule_vec: Vec<Rule> = rules.iter_rules()
    .map(|syntax| Rule::new(syntax.clone()))
    .collect();
let rules_db = Arc::new(RulesDatabase::from_rules(rule_vec)?);

// Create scanner and scan
let scanner = Scanner::new(rules_db);
let findings = scanner.scan_file("config.yml")?;

for finding in findings {
    println!("{}: {}", finding.rule_name, finding.secret);
}
```

For complete documentation, see **[docs/LIBRARY.md](docs/LIBRARY.md)**.

# Exit Codes

| Code | Meaning                       |
| ---- | ----------------------------- |
| 0    | No findings                   |
| 200  | Findings discovered           |
| 205  | Validated findings discovered |

# Lineage and Evolution

Kingfisher began as an internal fork of Nosey Parker, used as a high-performance foundation for secret detection. 

Since then it has evolved far beyond that starting point, introducing live validation, hundreds of new rules, additional scan targets, and major architectural changes across nearly every subsystem.

**Key areas of evolution**
- **Live validation** of detected secrets directly within rules  
- **Hundreds of new built-in rules** and an expanded YAML rule schema  
- **Baseline management** to suppress known findings over time  
- **Tree-sitter parsing** layered on Hyperscan for language-aware detection  
- **More scan targets** (GitLab, Bitbucket, Gitea, Jira, Confluence, Slack, S3, GCS, Docker, Hugging Face, etc.)  
- **Compressed Files** scanning support added
- **New storage model** (in-memory + Bloom filter, replacing SQLite)  
- **Unified workflow** with JSON/BSON/SARIF outputs  
- **Cross-platform builds** for Linux, macOS, and Windows

# Roadmap

- More rules
- More targets
- Please file a [feature request](https://github.com/mongodb/kingfisher/issues), or open a PR, if you have features you'd like added

# License

[Apache2 License](LICENSE)
