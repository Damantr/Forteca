use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct ConfigT {
    pub server: ServerConfig,
    pub tls: TlsConfig,
    pub routes: Vec<RouteConfig>,
}

#[derive(Debug, Deserialize)]
pub struct TlsConfig {
    pub cert: String,
    pub key: String,
}

#[derive(Debug, Deserialize)]
pub struct ServerConfig {
    pub listen: String,
}

#[derive(Debug, Deserialize)]
pub struct RouteConfig {
    pub domain: String,
    pub upstream: String,
    pub protocol: String,
    pub tls_server_name: Option<String>,
}

impl ConfigT {
    pub fn load(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;

        let config: ConfigT = toml::from_str(&content)?;

        Ok(config)
    }
}
