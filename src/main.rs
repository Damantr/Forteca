use async_trait::async_trait;
use modsecurity::engine::ModSecurity;
use pingora::{
    prelude::HttpPeer,
    proxy::{ProxyHttp, Session, http_proxy_service},
    server::Server,
};
use std::sync::Arc;
mod modsecurity;

use modsecurity::rules::Rules;

use crate::modsecurity::transaction::{Transaction, WafDecision};

pub struct RProxy;

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
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let _waf = ModSecurity::new().expect("Could not initialize");
    let mut rules = Rules::new()?;
    rules.add("SecRuleEngine On")?;
    rules.add(r#"SecRule REQUEST_URI "@contains /admin" "id:1001,phase:1,deny,status:403""#)?;
    rules.add(
    r#"SecRule REQUEST_HEADERS:User-Agent "@contains BadBot" "id:1002,phase:1,deny,status:403""#)?;
    rules.add(
    r#"SecRule REQUEST_URI "@streq /old" "id:1004,phase:1,redirect:'https://example.com/new',status:302""#
)?;

    rules.add("SecRequestBodyAccess On")?;

    rules.add(r#"SecRule ARGS:username "@streq admin" "id:1003,phase:2,deny,status:403""#)?;

    let mut tx = Transaction::new(&_waf, &rules)?;

    tx.process_uri("/admin", "GET", "1.1")?;
    tx.process_request_headers()?;

    let mut server = Server::new(None).unwrap();
    server.bootstrap();
    let mut proxy = http_proxy_service(&server.configuration, RProxy);
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
        rules.add("SecRuleEngine On");
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
}
