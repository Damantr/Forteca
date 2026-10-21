use async_trait::async_trait;
use pingora::{
    Error, ErrorType,
    prelude::HttpPeer,
    proxy::{ProxyHttp, Session, http_proxy_service},
    server::Server,
};
use std::sync::Arc;

use bytes::Bytes;
mod modsecurity;
mod waf_client;

use config_model::ConfigT;

mod config_model;

use crate::waf_client::{WafClient, WafRequest};

use crate::modsecurity::{
    engine::ModSecurity,
    inspect_headers, inspect_request,
    rules::Rules,
    transaction::{Transaction, WafDecision},
};

struct RProxy {
    config: Arc<ConfigT>,
    waf: WafClient,
}

#[derive(Default)]
struct WafCtx {
    request: Option<WafRequest>,
    body: Vec<u8>,
}

const MAX_BODY_SIZE: usize = 1024 * 1024;

#[async_trait]
impl ProxyHttp for RProxy {
    type CTX = WafCtx;
    fn new_ctx(&self) -> Self::CTX {
        WafCtx::default()
    }
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        let route = &self.config.routes[0];

        let peer = HttpPeer::new(
            &route.upstream,
            route.protocol == "https",
            route.tls_server_name.clone().unwrap_or_default(),
        );

        Ok(Box::new(peer))
    }
    async fn request_filter(
        &self,
        _session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<bool> {
        let req = _session.req_header();

        if req
            .headers
            .get("content-length")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.parse::<u64>().ok())
            .is_some_and(|length| length > MAX_BODY_SIZE as u64)
        {
            _session.respond_error(413).await?;
            return Ok(true);
        }

        let method = req.method.to_string();
        let uri = req.uri.to_string();

        let version = match req.version {
            pingora::http::Version::HTTP_10 => "1.0",
            pingora::http::Version::HTTP_11 => "1.1",
            pingora::http::Version::HTTP_2 => "2.0",
            _ => {
                return Err(pingora::Error::new(pingora::ErrorType::InternalError));
            }
        }
        .to_string();

        let headers: Vec<(Vec<u8>, Vec<u8>)> = req
            .headers
            .iter()
            .map(|(name, value)| (name.as_str().as_bytes().to_vec(), value.as_bytes().to_vec()))
            .collect();

        ctx.request = Some(WafRequest {
            method,
            uri,
            version,
            headers,
            body: Vec::new(),
        });

        Ok(false)
    }

    async fn request_body_filter(
        &self,
        _session: &mut Session,
        body: &mut Option<Bytes>,
        end_of_stream: bool,
        ctx: &mut Self::CTX,
    ) -> pingora::Result<()> {
        if let Some(chunk) = body.take() {
            if chunk.len() > MAX_BODY_SIZE.saturating_sub(ctx.body.len()) {
                return Err(Error::explain(
                    ErrorType::HTTPStatus(413),
                    "Request body too large",
                ));
            }

            ctx.body.extend_from_slice(&chunk);
        }

        if end_of_stream {
            let mut request = ctx
                .request
                .take()
                .ok_or_else(|| Error::explain(ErrorType::InternalError, "Missing WAF request"))?;

            request.body = std::mem::take(&mut ctx.body);

            let body_to_forward = Bytes::copy_from_slice(&request.body);

            let decision = self.waf.inspect(request).await;

            match decision {
                Ok(WafDecision::Allow) => {
                    *body = Some(body_to_forward);
                }

                Ok(WafDecision::Block(status)) => {
                    return Err(Error::explain(
                        ErrorType::HTTPStatus(status),
                        "Blocked by WAF",
                    ));
                }

                Ok(WafDecision::Redirect { .. }) => {
                    return Err(Error::explain(
                        ErrorType::InternalError,
                        "Redirect during body inspection",
                    ));
                }

                Err(error) => {
                    eprintln!("WAF error: {error}");

                    return Err(Error::explain(
                        ErrorType::InternalError,
                        "WAF inspection failed",
                    ));
                }
            }
        } else {
            *body = Some(Bytes::new());
        }

        Ok(())
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let config: Arc<ConfigT> = Arc::new(ConfigT::load("config_dev.toml")?);
    println!("{:#?}", config);

    let waf = WafClient::start()?;
    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    let mut proxy = http_proxy_service(
        &server.configuration,
        RProxy {
            waf,
            config: Arc::clone(&config),
        },
    );
    proxy.add_tls(&config.server.listen, &config.tls.key, &config.tls.key)?;
    server.add_service(proxy);
    server.run_forever();
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_redirect_is_persistent() -> Result<(), Box<dyn std::error::Error>> {
        let _waf = ModSecurity::new().expect("Could not initialize");
        let mut rules = Rules::new()?;
        rules.add("SecRuleEngine On")?;
        rules.add(
        r#"SecRule REQUEST_URI "@streq /old" "id:1004,phase:1,redirect:'https://example.com/new',status:302""#
        )?;

        let mut tx = Transaction::new(&_waf, &rules)?;
        tx.process_uri("/old", "GET", "1.1")?;
        tx.process_request_headers()?;

        let first = tx.intervention();
        let second = tx.intervention();

        assert_eq!(first, second);
        assert_eq!(
            first,
            WafDecision::Redirect {
                status: 302,
                url: "https://example.com/new".into(),
            }
        );
        Ok(())
    }

    #[test]
    fn test_reuse_engine_and_rules() -> Result<(), String> {
        use std::time::Instant;
        let engine = ModSecurity::new()?;
        let mut rules = Rules::new()?;

        rules.add_file("src/rules/modsecurity.conf")?;
        rules.add_file("src/rules/custom.conf")?;

        let start = Instant::now();

        for _ in 0..10_000 {
            let decision = inspect_headers(&engine, &rules, "GET", "/hello", "1.1", &[])?;

            assert_eq!(decision, WafDecision::Allow);
        }

        let elapsed = start.elapsed();

        println!("Total: {elapsed:?}");
        println!("Average: {:?}", elapsed / 10_000);

        Ok(())
    }
    #[test]
    fn test_phase2() -> Result<(), String> {
        let engine = ModSecurity::new()?;
        let mut rules = Rules::new()?;

        rules.add_file("src/rules/modsecurity.conf")?;
        rules.add_file("src/rules/custom.conf")?;

        let headers = vec![(
            b"Content-Type".to_vec(),
            b"application/x-www-form-urlencoded".to_vec(),
        )];

        let decision = inspect_request(
            &engine,
            &rules,
            "POST",
            "/login",
            "1.1",
            &headers,
            b"username=admin",
        )?;

        assert_eq!(decision, WafDecision::Block(403));

        Ok(())
    }
}
