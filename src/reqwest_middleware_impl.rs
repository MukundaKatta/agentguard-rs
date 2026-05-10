//! reqwest-middleware integration.

use crate::allow::Allowlist;
use async_trait::async_trait;
use reqwest::{Request, Response};
use reqwest_middleware::{Middleware, Next};

/// Middleware that rejects requests whose URL fails the [`Allowlist`].
///
/// Install in `reqwest_middleware::ClientBuilder::with`; any agent tool
/// using the wrapped client gets sandboxed without changing its code.
#[derive(Clone)]
pub struct GuardMiddleware {
    allow: Allowlist,
}

impl GuardMiddleware {
    /// Wrap an [`Allowlist`] as middleware.
    pub fn new(allow: Allowlist) -> Self {
        Self { allow }
    }
}

#[async_trait]
impl Middleware for GuardMiddleware {
    async fn handle(
        &self,
        req: Request,
        ext: &mut http::Extensions,
        next: Next<'_>,
    ) -> reqwest_middleware::Result<Response> {
        let url = req.url().to_string();
        if let Err(e) = self.allow.check(&url) {
            return Err(reqwest_middleware::Error::Middleware(anyhow::anyhow!(e)));
        }
        next.run(req, ext).await
    }
}
