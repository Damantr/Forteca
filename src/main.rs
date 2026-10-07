use async_trait::async_trait;
use pingora::{
    prelude::HttpPeer,
    proxy::{ProxyHttp, Session, http_proxy_service},
    server::Server,
};
use std::sync::Arc;

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

fn main() {
    let mut server = Server::new(None).unwrap();
    server.bootstrap();
    let mut proxy = http_proxy_service(&server.configuration, RProxy);
    proxy
        .add_tls("0.0.0.0:3001", "cert.pem", "key.pem")
        .unwrap();
    server.add_service(proxy);
    server.run_forever();
}
