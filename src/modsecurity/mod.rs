use crate::modsecurity::transaction::WafDecision;
use crate::modsecurity::{engine::ModSecurity, rules::Rules};

pub mod engine;
mod ffi;
pub mod rules;
pub mod transaction;

pub fn inspect_headers(
    engine: &ModSecurity,
    rules: &Rules,
    method: &str,
    uri: &str,
    version: &str,
    headers: &[(Vec<u8>, Vec<u8>)],
) -> Result<WafDecision, String> {
    let mut tx = transaction::Transaction::new(engine, rules)?;
    tx.process_uri(uri, method, version)?;

    for (name, value) in headers {
        let name = std::str::from_utf8(name).map_err(|e| e.to_string())?;

        let value = std::str::from_utf8(value).map_err(|e| e.to_string())?;

        tx.add_request_header(name, value)?;
    }

    tx.process_request_headers()?;

    Ok(tx.intervention())
}
