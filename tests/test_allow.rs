use agentguard::{Allowlist, GuardError};

#[test]
fn empty_allowlist_rejects_everything() {
    let a = Allowlist::new();
    let err = a.check("https://api.openai.com/v1/chat").unwrap_err();
    assert!(matches!(err, GuardError::HostNotAllowed { .. }));
}

#[test]
fn exact_domain_match() {
    let a = Allowlist::new().domain("api.openai.com");
    a.check("https://api.openai.com/v1/chat").unwrap();
    a.check("https://api.openai.com/").unwrap();
}

#[test]
fn exact_domain_does_not_match_subdomain() {
    let a = Allowlist::new().domain("openai.com");
    let err = a.check("https://api.openai.com/").unwrap_err();
    assert!(matches!(err, GuardError::HostNotAllowed { .. }));
}

#[test]
fn subdomains_of_matches_apex_and_descendants() {
    let a = Allowlist::new().subdomains_of("anthropic.com");
    a.check("https://anthropic.com/").unwrap();
    a.check("https://api.anthropic.com/v1/messages").unwrap();
    a.check("https://us.api.anthropic.com/").unwrap();
}

#[test]
fn subdomains_of_rejects_unrelated_hosts() {
    let a = Allowlist::new().subdomains_of("anthropic.com");
    let err = a.check("https://attacker.com/").unwrap_err();
    assert!(matches!(err, GuardError::HostNotAllowed { .. }));
}

#[test]
fn case_insensitive() {
    let a = Allowlist::new().subdomains_of("Anthropic.com");
    a.check("https://API.ANTHROPIC.COM/").unwrap();
}

#[test]
fn invalid_url_errors() {
    let a = Allowlist::new().domain("a.com");
    let err = a.check("not a url").unwrap_err();
    assert!(matches!(err, GuardError::InvalidUrl(_)));
}

#[test]
fn scheme_not_allowed() {
    let a = Allowlist::new().domain("a.com");
    let err = a.check("file:///etc/passwd").unwrap_err();
    assert!(matches!(err, GuardError::SchemeNotAllowed(_)));
}

#[test]
fn allow_custom_schemes() {
    let a = Allowlist::new()
        .domain("acme.com")
        .allow_schemes(["https", "wss"]);
    a.check("wss://acme.com/socket").unwrap();
    let err = a.check("ftp://acme.com/").unwrap_err();
    assert!(matches!(err, GuardError::SchemeNotAllowed(_)));
}

#[test]
fn is_allowed_host_works_without_url_parsing() {
    let a = Allowlist::new().domain("a.com").subdomains_of("b.com");
    assert!(a.is_allowed_host("a.com"));
    assert!(!a.is_allowed_host("sub.a.com"));
    assert!(a.is_allowed_host("b.com"));
    assert!(a.is_allowed_host("x.b.com"));
    assert!(!a.is_allowed_host("c.com"));
}

#[test]
fn trailing_dot_fqdn_matches_exact_rule() {
    // `anthropic.com.` is the fully-qualified form of `anthropic.com` and
    // resolves to the same servers, so it must satisfy the same rule.
    let a = Allowlist::new().domain("api.anthropic.com");
    a.check("https://api.anthropic.com./v1/messages").unwrap();
    assert!(a.is_allowed_host("api.anthropic.com."));
}

#[test]
fn trailing_dot_fqdn_matches_subdomains_rule() {
    let a = Allowlist::new().subdomains_of("anthropic.com");
    a.check("https://anthropic.com./").unwrap();
    a.check("https://api.anthropic.com./v1/messages").unwrap();
    assert!(a.is_allowed_host("anthropic.com."));
    assert!(a.is_allowed_host("api.anthropic.com."));
}

#[test]
fn trailing_dot_in_rule_is_normalized() {
    let a = Allowlist::new()
        .domain("exact.com.")
        .subdomains_of("wild.com.");
    a.check("https://exact.com/").unwrap();
    a.check("https://exact.com./").unwrap();
    a.check("https://x.wild.com/").unwrap();
    a.check("https://x.wild.com./").unwrap();
}

#[test]
fn trailing_dot_does_not_widen_matching() {
    // Stripping the trailing dot must not let an unrelated host through.
    let a = Allowlist::new().subdomains_of("anthropic.com");
    assert!(a.check("https://evil.com./").is_err());
    assert!(!a.is_allowed_host("evil.com."));
    // A malformed double-trailing-dot host stays rejected.
    assert!(!a.is_allowed_host("anthropic.com.."));
}

#[test]
fn multi_rule_combine() {
    let a = Allowlist::new()
        .domain("exact.com")
        .subdomains_of("wild.com");
    a.check("https://exact.com/").unwrap();
    a.check("https://x.y.wild.com/").unwrap();
    a.check("https://wild.com/").unwrap();
    assert!(a.check("https://x.exact.com/").is_err());
}
