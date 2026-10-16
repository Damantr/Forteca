use async_trait::async_trait;
use pingora::{
    prelude::HttpPeer,
    proxy::{ProxyHttp, Session, http_proxy_service},
    server::Server,
};
use std::sync::Arc;
mod modsecurity;
mod waf_client;

use crate::waf_client::{WafClient, WafRequest};

use crate::modsecurity::{
    engine::ModSecurity,
    inspect_headers,
    rules::Rules,
    transaction::{Transaction, WafDecision},
};

struct RProxy {
    waf: WafClient,
}

#[async_trait]
impl ProxyHttp for RProxy {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}
    async fn upstream_peer(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<Box<HttpPeer>> {
        let mut peer = Box::new(HttpPeer::new(
            "127.0.0.1:7275",
            true,
            "localhost".to_string(),
        ));
        peer.options.verify_cert = false;
        peer.options.verify_hostname = false;
        Ok(peer)
    }

    async fn request_filter(
        &self,
        _session: &mut Session,
        _ctx: &mut Self::CTX,
    ) -> pingora::Result<bool> {
        let req = _session.req_header();

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

        let decision = self
            .waf
            .inspect(WafRequest {
                method,
                uri,
                version,
                headers,
            })
            .await;

        match decision {
            Ok(WafDecision::Allow) => Ok(false),

            Ok(WafDecision::Block(status)) => {
                _session
                    .respond_error_with_body(status, "Blocked by WAF".into())
                    .await?;

                Ok(true)
            }

            Ok(WafDecision::Redirect { status, url }) => {
                let mut response = pingora::http::ResponseHeader::build(status, None)?;

                response.insert_header("Location", url.as_str())?;

                _session
                    .write_response_header(Box::new(response), true)
                    .await?;

                Ok(true)
            }
            Err(error) => {
                eprintln!("WAF error: {}", error);
                _session
                    .respond_error_with_body(500, "WAF inspection failed".into())
                    .await?;

                Ok(true)
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let waf = WafClient::start()?;
    let mut server = Server::new(None).unwrap();
    server.bootstrap();

    let mut proxy = http_proxy_service(&server.configuration, RProxy { waf });
    proxy
        .add_tls("0.0.0.0:3001", "cert.pem", "key.pem")
        .unwrap();
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
}
