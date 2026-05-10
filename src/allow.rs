use thiserror::Error;
use url::Url;

/// Reasons a request is blocked.
#[derive(Debug, Clone, Error)]
pub enum GuardError {
    /// The URL string couldn't be parsed.
    #[error("invalid URL: {0}")]
    InvalidUrl(String),
    /// The URL has no host (e.g. `file://` or relative).
    #[error("URL has no host: {0}")]
    NoHost(String),
    /// The host isn't on the allowlist.
    #[error("host not on allowlist: {host}")]
    HostNotAllowed {
        /// The rejected host.
        host: String,
    },
    /// The scheme isn't allowed (default allows only http/https).
    #[error("scheme not allowed: {0}")]
    SchemeNotAllowed(String),
}

#[derive(Debug, Clone)]
enum Rule {
    Exact(String),
    SubdomainsOf(String),
}

/// Declarative allowlist of domains an agent's tools may fetch.
///
/// By default only `http` and `https` schemes pass. Add domain rules with
/// [`domain`](Self::domain) (exact match) or [`subdomains_of`](Self::subdomains_of)
/// (apex + any subdomain). Calls to [`check`](Self::check) return
/// `Ok(())` if allowed, `Err(GuardError)` otherwise.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    rules: Vec<Rule>,
    allowed_schemes: Vec<String>,
}

impl Allowlist {
    /// Empty allowlist; everything is rejected until you add rules.
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            allowed_schemes: vec!["http".into(), "https".into()],
        }
    }

    /// Add an exact-match domain rule. Both the apex and an explicit `www.`
    /// subdomain are matched only by their literal string; for broader
    /// matching use [`subdomains_of`](Self::subdomains_of).
    pub fn domain(mut self, host: impl Into<String>) -> Self {
        self.rules.push(Rule::Exact(host.into().to_lowercase()));
        self
    }

    /// Allow the apex host and any subdomain (e.g. `subdomains_of("acme.com")`
    /// permits `acme.com`, `api.acme.com`, `a.b.acme.com`, …).
    pub fn subdomains_of(mut self, apex: impl Into<String>) -> Self {
        self.rules
            .push(Rule::SubdomainsOf(apex.into().to_lowercase()));
        self
    }

    /// Override the allowed URL schemes (default `["http", "https"]`).
    pub fn allow_schemes<I, S>(mut self, schemes: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.allowed_schemes = schemes.into_iter().map(|s| s.into().to_lowercase()).collect();
        self
    }

    /// Check whether `url` is allowed. Returns `Ok(())` or a [`GuardError`].
    pub fn check(&self, url: &str) -> Result<(), GuardError> {
        let parsed = Url::parse(url).map_err(|_| GuardError::InvalidUrl(url.to_string()))?;
        let scheme = parsed.scheme().to_lowercase();
        if !self.allowed_schemes.contains(&scheme) {
            return Err(GuardError::SchemeNotAllowed(scheme));
        }
        let host = parsed
            .host_str()
            .ok_or_else(|| GuardError::NoHost(url.to_string()))?
            .to_lowercase();
        if self.is_allowed_host(&host) {
            Ok(())
        } else {
            Err(GuardError::HostNotAllowed { host })
        }
    }

    /// True if `host` matches any rule. Lower-level than `check` (skips URL parsing).
    pub fn is_allowed_host(&self, host: &str) -> bool {
        let host = host.to_lowercase();
        for rule in &self.rules {
            match rule {
                Rule::Exact(d) => {
                    if host == *d {
                        return true;
                    }
                }
                Rule::SubdomainsOf(apex) => {
                    if host == *apex
                        || host.ends_with(&format!(".{apex}"))
                    {
                        return true;
                    }
                }
            }
        }
        false
    }
}
