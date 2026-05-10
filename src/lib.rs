//! Network egress firewall for AI agent tools.
//!
//! Build a declarative [`Allowlist`] and call [`Allowlist::check`] before any
//! agent-initiated HTTP request. With the `reqwest` feature, install
//! [`GuardMiddleware`] in your `reqwest_middleware::ClientBuilder` and the
//! check happens automatically.
//!
//! # Quick start
//!
//! ```
//! use agentguard::Allowlist;
//!
//! let allow = Allowlist::new()
//!     .domain("api.openai.com")
//!     .domain("api.anthropic.com")
//!     .subdomains_of("amazonaws.com");
//!
//! allow.check("https://api.openai.com/v1/chat/completions").unwrap();
//! allow.check("https://s3.us-east-1.amazonaws.com/bucket/key").unwrap();
//!
//! // Anything else is rejected:
//! assert!(allow.check("https://evil.example/leak").is_err());
//! ```
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![warn(rust_2018_idioms)]

mod allow;

pub use crate::allow::{Allowlist, GuardError};

#[cfg(feature = "reqwest")]
mod reqwest_middleware_impl;
#[cfg(feature = "reqwest")]
pub use crate::reqwest_middleware_impl::GuardMiddleware;
