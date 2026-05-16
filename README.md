# agentguard

[![crates.io](https://img.shields.io/crates/v/agentguard.svg)](https://crates.io/crates/agentguard)
[![docs.rs](https://docs.rs/agentguard/badge.svg)](https://docs.rs/agentguard)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

Network egress firewall for AI agent tools. Declarative domain allowlist; throws on violation.

```toml
[dependencies]
agentguard = "0.1"
# Or, with reqwest-middleware integration:
agentguard = { version = "0.1", features = ["reqwest"] }
```

## Why

Your agent's tools call out to the network. Without a sandbox, a prompt injection or a confused-deputy bug can exfiltrate secrets to attacker-controlled domains. `agentguard` is the smallest possible primitive that stops it: a declarative allowlist you check before each call (or install once as `reqwest-middleware` and forget).

## Quick start

```rust
use agentguard::Allowlist;

let allow = Allowlist::new()
    .domain("api.openai.com")
    .domain("api.anthropic.com")
    .subdomains_of("amazonaws.com");   // permits s3.us-east-1.amazonaws.com etc.

allow.check("https://api.openai.com/v1/chat").unwrap();
allow.check("https://s3.us-east-1.amazonaws.com/bucket/key").unwrap();

// Everything else is rejected:
assert!(allow.check("https://evil.example/leak").is_err());
assert!(allow.check("file:///etc/passwd").is_err());
```

## With `reqwest-middleware`

Enable the `reqwest` feature, then plug `GuardMiddleware` into a `reqwest_middleware::ClientBuilder`:

```rust,no_run
# #[cfg(feature = "reqwest")]
# {
use agentguard::{Allowlist, GuardMiddleware};
use reqwest::Client;
use reqwest_middleware::ClientBuilder;

let allow = Allowlist::new().subdomains_of("anthropic.com");
let client = ClientBuilder::new(Client::new())
    .with(GuardMiddleware::new(allow))
    .build();

// Calls to anthropic.com pass; everything else returns a Middleware error.
# }
```

## Rules

- `.domain("api.openai.com")` — exact-match host. `sub.api.openai.com` is **not** allowed.
- `.subdomains_of("anthropic.com")` — apex + any subdomain. `anthropic.com`, `api.anthropic.com`, `us.api.anthropic.com` all pass.
- `.allow_schemes(["https", "wss"])` — override the default `["http", "https"]`.

Order doesn't matter — a URL is allowed if it matches any rule.

## What it doesn't do

- No DNS resolution; matches on the URL host string. (DNS rebinding is a different threat — pin IPs at the resolver level.)
- No path filtering; full host gates everything.
- No regex; subdomain matching is structural (`.endsWith(.apex)`).

## Sibling: JS `@mukundakatta/agentguard`

JS users: see [@mukundakatta/agentguard](https://www.npmjs.com/package/@mukundakatta/agentguard) on npm.

## License

MIT

## Repository Health

This repository includes a dependency-free health check for core documentation, metadata, and CI wiring. Run it locally before publishing changes:

```sh
python3 scripts/check_repository_health.py
```

The same check runs in GitHub Actions on pushes and pull requests.
