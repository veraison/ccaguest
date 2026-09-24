// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use crate::error::{Error, Result};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use log::{debug, warn};
use rand::{TryRng, rng};
use regl::attesters::{
    Attester,
    cca::{CcaError, CcaRatsdAttester, CcaSimulatedAttester, CcaTsmAttester},
};
use std::{
    fs::{File, read_to_string},
    io::Read,
    path::PathBuf,
    vec,
};

/// Regl attester backend(https://github.com/veraison/rust-regl) to use for evidence generation..
///
/// | Variant     | Description                                              |
/// |-------------|----------------------------------------------------------|
/// | `Ratsd`     | Connects to a running RATSD daemon (default)             |
/// | `Tsm`       | Reads from the Linux kernel configfs-tsm interface       |
/// | `Sim`       | Builds a CCA token from JSON claims & JWK keys (no HW)   |
#[derive(Debug, Clone, Default, clap::ValueEnum)]
pub enum AttesterKind {
    /// Fetch evidence from a RATSD daemon (default ratsd_url: http://localhost:8895).
    #[default]
    Ratsd,
    /// Collect evidence from the Linux TSM subsystem (requires CCA hardware).
    Tsm,
    /// Build a simulated CCA token from local claims/key files (for testing).
    Sim,
}

/// Generate attestation evidence using AttesterKind and nonce
pub fn generate_evidence(
    kind: &AttesterKind,
    ratsd_url: Option<&str>,
    sim_claims: Option<&PathBuf>,
    sim_iak: Option<&PathBuf>,
    nonce: &[u8],
) -> Result<Vec<u8>> {
    Ok(build_attester(kind, ratsd_url, sim_claims, sim_iak)?.get_evidence(nonce)?)
}

pub fn build_attester(
    kind: &AttesterKind,
    ratsd_url: Option<&str>,
    sim_claims: Option<&PathBuf>,
    sim_iak: Option<&PathBuf>,
) -> Result<Box<dyn Attester<AttesterError = CcaError>>> {
    match kind {
        AttesterKind::Ratsd => {
            let url = ratsd_url.unwrap_or_else(|| {
                warn!("using ratsd-url: http://localhost:8895");
                "http://localhost:8895"
            });
            Ok(Box::new(CcaRatsdAttester::with_url(url)?))
        }
        AttesterKind::Tsm => Ok(Box::new(CcaTsmAttester::default())),
        AttesterKind::Sim => create_sim_attester(sim_claims, sim_iak),
    }
}

fn create_sim_attester(
    sim_claims: Option<&PathBuf>,
    sim_iak: Option<&PathBuf>,
) -> Result<Box<dyn Attester<AttesterError = CcaError>>> {
    let claims = match sim_claims {
        Some(path) => {
            debug!("using cca-claims.json file: {path:?}");
            read_to_string(path)?
        }
        None => include_str!("../test/json/cca-claims.json").to_string(),
    };

    let iak = match sim_iak {
        Some(path) => {
            debug!("using iak.jwk file: {path:?}");
            read_to_string(path)?
        }
        None => include_str!("../test/json/iak.jwk").to_string(),
    };

    Ok(Box::new(CcaSimulatedAttester::new(&claims, &iak, None)?))
}

/// Generates a random 64-byte nonce for attestation.
/// Uses a cryptographically secure random number generator to generate
/// a random nonce suitable for CCA attestation.
pub fn generate_nonce() -> Result<Vec<u8>> {
    let mut nonce = vec![0u8; 64];

    // the return type of `try_fill_bytes` is `Result<(), Infallible>`, so we can safely unwrap it here
    rng()
        .try_fill_bytes(&mut nonce)
        .expect("failed to generate random nonce");

    Ok(nonce.to_vec())
}

/// Parse and return whichever encoding the nonce is provided with.
/// If no nonce is given, generate a random nonce and return. The
/// returned nonce is always 64B.
pub fn get_nonce(
    nonce_raw: Option<PathBuf>,
    nonce_hex: Option<String>,
    nonce_b64: Option<String>,
    nonce_b64url: Option<String>,
) -> Result<Vec<u8>> {
    let mut nonce = match (nonce_raw, nonce_hex, nonce_b64, nonce_b64url) {
        // Bounded read limit of 128B puts a ceiling on all kinds of decoding that the nonce
        // might be in. E.g., raw nonce needs to read 64B, hex needs 128B, base64 needs 88B.
        (Some(raw), None, None, None) => bounded_file_read(raw, 128)?,

        (None, Some(data), None, None) => hex::decode(bounded_read(&data, 128)?.as_slice())
            .map_err(|e| Error::custom(format!("hex-encoded nonce: {e}")))?,

        (None, None, Some(data), None) => STANDARD
            .decode(bounded_read(&data, 128)?.as_slice())
            .map_err(|e| Error::custom(format!("base64-encoded nonce: {e}")))?,

        (None, None, None, Some(data)) => URL_SAFE_NO_PAD
            .decode(bounded_read(&data, 128)?.as_slice())
            .map_err(|e| Error::custom(format!("base64url-encoded nonce: {e}")))?,

        (None, None, None, None) => generate_nonce()?,

        _ => unreachable!("nonce arguments should be mutually exclusive"),
    };

    // Resizing is needed in case the nonce wasn't long enough.
    nonce.resize(64, 0);

    Ok(nonce)
}

/// Read a limited number of bytes from file.
pub fn bounded_file_read(path: PathBuf, limit: usize) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(limit);

    File::open(path)?.take(limit as u64).read_to_end(&mut buf)?;

    Ok(buf)
}

/// Read a limited number of bytes from string.
pub fn bounded_read(s: &str, limit: usize) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(limit);

    buf.extend_from_slice(s.as_bytes());

    if buf.len() > limit {
        return Err(Error::custom(format!(
            "nonce input exceeds maximum length of {limit} bytes"
        )));
    }

    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bounded_file_read() {
        let path_buf = PathBuf::from("test/cbor/ccatoken.cbor");

        let result = bounded_file_read(path_buf, 1000);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1000);
    }

    #[test]
    fn test_valid_bounded_read() {
        let some_str = "ogB4I3RhZzphcm0uY29tLDIwMjU6Y2NhX3BsYXRmb3JtIzEuMC4wAaMAAgGhAIGBoQDZAjBYIH9FTEYCAQEAAAAAAAAAAAADAD4AAQAAAFBYAAAAAAAAAgA";

        let result = bounded_read(some_str, 128);
        assert!(result.is_ok())
    }

    #[test]
    fn test_invalid_bounded_read() {
        let some_str = "ogB4I3RhZzphcm0uY29tLDIwMjU6Y2NhX3BsYXRmb3JtIzEuMC4wAaMAAgGhAIGBoQDZAjBYIH9FTEYCAQEAAAAAAAAAAAADAD4AAQAAAFBYAAAAAAAAAgA";

        let result = bounded_read(some_str, 100);
        assert!(result.is_err())
    }
}
