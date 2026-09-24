// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use crate::{
    cli::CommonFlags,
    error::{Error, Result},
};
use clap::{Parser, Subcommand};
use log::{debug, info};
use regl::attesters::cca::utils::decode_cca_token;
use std::fs;
use std::path::PathBuf;
use url::Url;

const DEFAULT_NONCE_SIZE: usize = 64;

#[derive(Debug, Subcommand)]
pub enum VerifyCmd {
    /// Local verification.
    Local(Box<local::Args>),

    /// Remote verification.
    Remote(Box<remote::Args>),
}

pub fn cmd(command: VerifyCmd) -> Result<()> {
    match command {
        VerifyCmd::Local(args) => local::verify(*args),
        VerifyCmd::Remote(args) => remote::verify(*args),
    }
}

mod local {
    use super::*;
    use crate::coserv::{ResultType, get_reference_values, get_trust_anchor};
    use crate::evidence::{AttesterKind, generate_evidence, get_nonce};
    use crate::scheme::CcaCustomScheme;
    use crate::store::MemCoservStore;
    use crate::utils;
    use cover::{CcaScheme, Policy, Scheme, Verifier};
    use ear::RawValue;
    use std::collections::HashMap;

    #[derive(Debug, Parser)]
    pub struct Args {
        /// Path to an evidence file in CBOR format. If not provided, a new evidence will be generated at runtime using Regl.
        /// The nonce can be provided in either of the following forms:
        /// - A text file containing the raw nonce bytes.
        /// - A string containing a hex- or base64-encoded nonce.
        ///   The argument for that includes the nonce's encoding(--nonce_<raw | hex | base64 | base64url>).
        ///   If the nonce is not exactly 64B long, it is truncated or right-padded with 0s to make it 64B long.
        #[arg(short, long, value_parser=utils::validate_input_file_path,  conflicts_with_all = &["attester", "ratsd_url", "nonce_raw", "nonce_hex", "nonce_b64", "nonce_b64url"])]
        evidence: Option<PathBuf>,

        /// Regl attester backend to use for evidence generation.
        ///
        /// - `ratsd` (default) Connect to a RATSD daemon (required to pass the --ratsd-url argument)
        /// - `tsm`   Read from the Linux configfs-tsm interface (requires CCA hardware)
        /// - `sim`   Build a CCA token from default JSON claims & JWK (inside test/json/: cca-claims.json and iak.jwk)
        #[arg(short, long, value_enum, conflicts_with_all = &["evidence"], default_value_t = AttesterKind::Ratsd)]
        attester: AttesterKind,

        /// URL of the RATSD daemon to connect to. Required when --attester is set to `ratsd`. Defaults to `http://localhost:8895`.
        #[arg(long, value_parser = utils::validate_base_url)]
        ratsd_url: Option<String>,

        /// Path to ARM CCA claims file (JSON format) to build a simulated attester (i.e., when --attester is set to `sim`). Default to `test/json/cca-claims.json`.
        #[arg(long, value_parser = utils::validate_input_file_path)]
        sim_claims: Option<PathBuf>,

        /// Path to ARM CCA iak file (JWK format) to build a simulated attester (i.e., when --attester is set to `sim`). Default to `test/json/iak.jwk`.
        #[arg(long, value_parser = utils::validate_input_file_path)]
        sim_iak: Option<PathBuf>,

        /// Path to a text file containing nonce as raw bytes.
        #[arg(long, value_parser = utils::validate_input_file_path, conflicts_with_all = &["evidence", "nonce_hex", "nonce_b64", "nonce_b64url"])]
        nonce_raw: Option<PathBuf>,

        /// A hex-encoded nonce passed as a string.
        #[arg(long, conflicts_with_all = &["evidence","nonce_raw", "nonce_b64", "nonce_b64url"])]
        nonce_hex: Option<String>,

        /// A base64-encoded nonce passed as a string.
        #[arg(long, conflicts_with_all = &["evidence","nonce_raw", "nonce_hex", "nonce_b64url"])]
        nonce_b64: Option<String>,

        /// A base64url-encoded nonce passed as a string.
        #[arg(long, conflicts_with_all = &["evidence","nonce_raw", "nonce_hex", "nonce_b64"])]
        nonce_b64url: Option<String>,

        /// Path to the reference values file. Must be a CoSERV results file in CBOR format.
        #[arg(short = 'R', long, value_parser = utils::validate_input_file_path)]
        reference_values: Option<PathBuf>,

        /// Path to the trust anchor file. Must be a CoSERV results file in CBOR format.
        #[arg(short = 'T', long, value_parser = utils::validate_input_file_path)]
        trust_anchor: Option<PathBuf>,

        /// The base URL to a CoSERV service if endorsements are not present locally.
        /// Coserv service should support the result-type=collected.
        #[arg(short = 'S', long, value_parser = utils::validate_base_url, required_unless_present_all = ["reference_values", "trust_anchor"])]
        coserv_server: Option<String>,

        /// The path to an X509 certificate to bootstrap TLS handshakes with the CoSERV service.
        #[arg(short = 't', long, value_parser = utils::validate_input_file_path)]
        ca_cert: Option<PathBuf>,

        /// The path to the directory where local coserv results will be cached.
        /// If not specified, no local caching is performed, and all CoSERV requests
        /// will go to the server.
        #[arg(short = 'l', long, value_parser = utils::validate_input_directory_path)]
        local_cache: Option<PathBuf>,

        /// The server MUST sign CoSERV results. The command fails
        /// if the server does not support signing.
        #[arg(long, default_value_t = false)]
        must_sign: bool,

        /// Path to custom policy file for verification.
        #[arg(short = 'P', long = "policy", value_parser = utils::validate_input_file_path)]
        policy_path: Option<PathBuf>,

        /// Output file path for writing the attestation results. If not specified,
        /// the attestation results will be saved to default `ear.json` in the current working directory.
        #[arg(short, long, value_parser = utils::validate_output_path, default_value = "ear.json")]
        output: PathBuf,

        // Common flags for all commands.
        #[command(flatten)]
        common: CommonFlags,
    }

    /// Verify a CCA attestation evidence using a local verifier.
    ///
    /// This function performs local verification of a CCA attestation evidence using
    /// the CoVer library. Evidence can be provided as a CBOR file. If evidence is not
    /// provided, it will try to generate one at runtime. A nonce can be provided as well.
    /// Reference values and trust anchors can be provided either as CoSERV result files
    /// or can be fetched from a remote CoSERV service. A custom policy can also be provided
    /// for verification.
    pub fn verify(args: Args) -> Result<()> {
        debug!("Verify local");

        let Args {
            evidence,
            attester,
            ratsd_url,
            sim_claims,
            sim_iak,
            nonce_raw,
            nonce_hex,
            nonce_b64,
            nonce_b64url,
            reference_values,
            trust_anchor,
            coserv_server,
            ca_cert,
            local_cache,
            must_sign,
            policy_path,
            output,
            ..
        } = args;
        debug!(
            "Loaded arguments: \n
            evidence={evidence:?}, \n
            attester={attester:?}, \n
            ratsd_url={ratsd_url:?}, \n
            sim_claims={sim_claims:?}, \n
            sim_iak={sim_iak:?}, \n
            nonce_raw={nonce_raw:?}, \n
            nonce_hex={nonce_hex:?}, \n
            nonce_b64={nonce_b64:?}, \n
            nonce_b64url={nonce_b64url:?}, \n
            reference_values={reference_values:?}, \n
            trust_anchor={trust_anchor:?}, \n
            coserv_server={coserv_server:?}, \n
            ca_cert={ca_cert:?}, \n
            local_cache={local_cache:?}, \n
            must_sign={must_sign}, \n
            policy_path={policy_path:?}, \n
            output={output:?}"
        );

        utils::check_output_file(&output, args.common.force)?;

        let raw_evidence = match evidence {
            Some(file) => fs::read(file)?,
            None => {
                let nonce = get_nonce(nonce_raw, nonce_hex, nonce_b64, nonce_b64url)?;
                debug!("Generating attestation evidence using {attester:?} attester");
                generate_evidence(
                    &attester,
                    ratsd_url.as_deref(),
                    sim_claims.as_ref(),
                    sim_iak.as_ref(),
                    nonce.as_slice(),
                )?
            }
        };
        let evidence = decode_cca_token(&raw_evidence)?;

        // populate the MemCoservStore with the coserv results
        let mut coserv_store = MemCoservStore::new();

        // read endorsements from the provided files or fetch from remote coserv service
        if let Some(file) = reference_values {
            let ref_values = fs::read(&file)?;
            debug!("Reading reference values from file: {file:?}");
            coserv_store.add_coserv_cbor_bytes(ref_values.as_slice())?;
        } else {
            let impl_id_bytes = evidence.platform.implementation_id;
            debug!("got impl_id: {impl_id_bytes:?} from evidence");

            let Some(coserv_server) = &coserv_server else {
                return Err(Error::MissingField {
                    object: "args",
                    field: "coserv-server if reference values are not passed",
                });
            };
            debug!("Fetching reference values for impl_id");
            let result_rv = get_reference_values(
                impl_id_bytes,
                coserv_server,
                ca_cert.as_ref(),
                local_cache.as_ref(),
                must_sign,
                &ResultType::Collected,
            )?;
            debug!("Reference values: {:?}", result_rv);
            coserv_store.add_coserv(&result_rv)?;
        }

        if let Some(file) = trust_anchor {
            let ta_values = fs::read(&file)?;
            debug!("Reading trust anchors from file: {file:?}");
            coserv_store.add_coserv_cbor_bytes(ta_values.as_slice())?;
        } else {
            let inst_id_bytes = evidence.platform.instance_id;
            debug!("got inst_id: {inst_id_bytes:?} from evidence");

            let Some(coserv_server) = &coserv_server else {
                return Err(Error::MissingField {
                    object: "args",
                    field: "coserv-server if trust anchors are not passed",
                });
            };
            debug!("Fetching trust anchors for inst_id");
            let result_ta = get_trust_anchor(
                inst_id_bytes,
                coserv_server,
                ca_cert.as_ref(),
                local_cache.as_ref(),
                must_sign,
                &ResultType::Collected,
            )?;
            debug!("Trust anchors: {:?}", result_ta);
            coserv_store.add_coserv(&result_ta)?;
        }

        // load cca scheme with custom policy, if provided
        let scheme: Box<dyn Scheme> = if let Some(path) = policy_path {
            Box::new(CcaCustomScheme::new(&path)?)
        } else {
            Box::new(CcaScheme::new())
        };

        let mut schemes = HashMap::new();
        let scheme_name = scheme.name();
        schemes.insert(scheme_name.clone(), scheme);

        debug!(
            "using schemes: {}",
            schemes
                .keys()
                .map(|k| k.as_ref())
                .collect::<Vec<&str>>()
                .join(", ")
        );

        // create the verifier
        let verifier = Verifier::new(coserv_store, schemes);

        // Check if evidence format matches with supported profiles.
        if verifier.match_evidence(raw_evidence.as_slice()).is_none() {
            return Err(Error::custom("evidence format not supported"));
        }

        // appraise evidence and produce the attestation result
        let nonce = evidence.realm.challenge;
        let mut result = verifier.verify(&scheme_name, raw_evidence.as_slice(), Some(&nonce))?;

        // Add policy rules to policy claims of the submods
        for (policy_id, appraisal) in result.ear.submods.iter_mut() {
            let pol_rules = get_policy(policy_id, &result.policies)?;
            appraisal
                .policy_claims
                .insert("policy-rules".to_string(), RawValue::String(pol_rules));
        }

        debug!("Pretty print: {}", args.common.pretty);
        let ear_json = if args.common.pretty {
            serde_json::to_string_pretty(&result.ear)?
        } else {
            serde_json::to_string(&result.ear)?
        };
        info!("ear: {ear_json}");

        utils::write_output_to_file(&ear_json, &output)?;
        info!("EAR saved to: {:?}", output);

        Ok(())
    }

    // Get policy rules of a given policy ID
    fn get_policy(policy_id: &String, policies: &Vec<Policy>) -> Result<String> {
        for policy in policies {
            if policy.id == *policy_id {
                return Ok(policy.text.clone());
            }
        }
        Err(Error::Custom(
            "The ID from EAR will always be contained in list of policies returned by CoVER!"
                .into(),
        ))
    }

    #[cfg(test)]
    mod tests {

        use super::*;
        use serde_json::Value;

        fn get_ear(policy_path: Option<PathBuf>) -> Result<Value> {
            let temp_file = tempfile::NamedTempFile::new()?;
            let ear_path = temp_file.path().to_path_buf();

            let args = local::Args {
                evidence: Some("test/cbor/ccatoken.cbor".into()),
                attester: AttesterKind::Ratsd,
                ratsd_url: None,
                sim_claims: None,
                sim_iak: None,
                nonce_raw: None,
                nonce_hex: None,
                nonce_b64: None,
                nonce_b64url: None,
                coserv_server: None,
                reference_values: Some("test/cbor/rv_result.cbor".into()),
                trust_anchor: Some("test/cbor/ta_result.cbor".into()),
                ca_cert: None,
                local_cache: None,
                must_sign: false,
                policy_path,
                output: ear_path.clone(),
                common: CommonFlags {
                    pretty: true,
                    force: true,
                },
            };
            let result = local::verify(args);
            assert!(result.is_ok());

            let contents = fs::read_to_string(&ear_path)?;
            let ear: Value = serde_json::from_str(&contents)?;
            Ok(ear)
        }

        #[test]
        fn test_verify_local_no_policy() {
            let ear = get_ear(None).unwrap();
            assert!(&ear["submods"]["platform"]["ear.status"] == "affirming");
            assert!(&ear["submods"]["realm"]["ear.status"] == "warning");
        }

        #[test]
        fn test_verify_local_empty_policy() {
            let policy_path = PathBuf::from("test/policy/empty.rego");
            let ear = get_ear(Some(policy_path)).unwrap();
            assert!(&ear["submods"]["empty-custom"]["ear.status"] == "none");
        }

        #[test]
        fn test_verify_local_allow_all_policy() {
            let policy_path = PathBuf::from("test/policy/allow-all.rego");
            let ear = get_ear(Some(policy_path)).unwrap();
            assert!(&ear["submods"]["allow-all-custom"]["ear.status"] == "affirming");
        }

        #[test]
        fn test_verify_local_deny_all_policy() {
            let policy_path = PathBuf::from("test/policy/deny-all.rego");
            let ear = get_ear(Some(policy_path)).unwrap();
            assert!(&ear["submods"]["deny-all-custom"]["ear.status"] == "contraindicated");
        }
    }
}

mod remote {
    use super::*;
    use crate::evidence::{AttesterKind, generate_evidence, get_nonce};
    use crate::utils;
    use ear::{Algorithm, Ear};
    use tokio::runtime::Runtime;
    use veraison_apiclient::{
        ChallengeResponseBuilder, DiscoveryBuilder, Nonce, ServiceState, http::ConfigureHttp,
    };

    // TODO: update this to `application/eat+cwt; eat_profile="` once the Veraison service supports it.
    // and also update the related test files.
    // Evidence media type for CCA attestation evidence.
    const MEDIA_TYPE: &str =
        r#"application/eat-collection; profile="http://arm.com/CCA-SSD/1.0.0""#;

    #[derive(Debug, Parser)]
    pub struct Args {
        /// The base URL to a verification service.
        #[arg(short = 'S', long, value_parser = utils::validate_base_url)]
        verification_server: String,

        /// The path to an X509 certificate to bootstrap TLS handshakes with the verification service.
        #[arg(short = 't', long, value_parser = utils::validate_input_file_path)]
        ca_cert: Option<PathBuf>,

        /// The path to the directory where local verification discovery document will be cached.
        /// If not specified, no local caching is performed, and all disocvery document requests
        /// will go to the server.
        #[arg(short = 'l', long, value_parser = utils::validate_input_directory_path)]
        local_cache: Option<PathBuf>,

        /// Path to an evidence file in CBOR format. If not provided, a new evidence will be generated at runtime using Regl.
        /// The nonce can be provided in either of the following forms:
        /// - A text file containing the raw nonce bytes.
        /// - A string containing a hex- or base64-encoded nonce.
        ///   The argument for that includes the nonce's encoding(--nonce_<raw | hex | base64 | base64url>).
        ///   If the nonce is not exactly 64B long, it is truncated or right-padded with 0s to make it 64B long.
        #[arg(short, long, value_parser=utils::validate_input_file_path,  conflicts_with_all = &["attester", "ratsd_url", "nonce_raw", "nonce_hex", "nonce_b64", "nonce_b64url"])]
        evidence: Option<PathBuf>,

        /// Regl attester backend to use for evidence generation.
        ///
        /// - `ratsd` (default) Connect to a RATSD daemon (required to pass the --ratsd-url argument)
        /// - `tsm`   Read from the Linux configfs-tsm interface (requires CCA hardware)
        /// - `sim`   Build a CCA token from default JSON claims & JWK (inside test/json/: cca-claims.json and iak.jwk)
        #[arg(short, long, value_enum, conflicts_with_all = &["evidence"], default_value_t = AttesterKind::Ratsd)]
        attester: AttesterKind,

        /// URL of the RATSD daemon to connect to. Required when --attester is set to `ratsd`. Defaults to `http://localhost:8895`.
        #[arg(long, value_parser = utils::validate_base_url)]
        ratsd_url: Option<String>,

        /// Path to ARM CCA claims file (JSON format) to build a simulated attester (i.e., when --attester is set to `sim`). Default to `test/json/cca-claims.json`.
        #[arg(long, value_parser = utils::validate_input_file_path)]
        sim_claims: Option<PathBuf>,

        /// Path to ARM CCA iak file (JWK format) to build a simulated attester (i.e., when --attester is set to `sim`). Default to `test/json/iak.jwk`.
        #[arg(long, value_parser = utils::validate_input_file_path)]
        sim_iak: Option<PathBuf>,

        /// Path to a text file containing nonce as raw bytes.
        #[arg(long, value_parser = utils::validate_input_file_path, conflicts_with_all = &["evidence", "nonce_hex", "nonce_b64", "nonce_b64url"])]
        nonce_raw: Option<PathBuf>,

        /// A hex-encoded nonce passed as a string.
        #[arg(long, conflicts_with_all = &["evidence","nonce_raw", "nonce_b64", "nonce_b64url"])]
        nonce_hex: Option<String>,

        /// A base64-encoded nonce passed as a string.
        #[arg(long, conflicts_with_all = &["evidence","nonce_raw", "nonce_hex", "nonce_b64url"])]
        nonce_b64: Option<String>,

        /// A base64url-encoded nonce passed as a string.
        #[arg(long, conflicts_with_all = &["evidence","nonce_raw", "nonce_hex", "nonce_b64"])]
        nonce_b64url: Option<String>,

        /// Output file path for writing the attestation results. If not specified,
        /// the attestation results will be saved to default `ear.jwt` in the current working directory.
        #[arg(short, long, value_parser = utils::validate_output_path, default_value = "ear.jwt")]
        output: PathBuf,

        // Common flags for all commands.
        #[command(flatten)]
        common: CommonFlags,
    }

    /// Verify a CCA attestation evidence using a remote verifier.
    pub fn verify(args: Args) -> Result<()> {
        debug!("Verify remotely");

        let Args {
            verification_server,
            ca_cert,
            local_cache,
            evidence,
            attester,
            ratsd_url,
            sim_claims,
            sim_iak,
            nonce_raw,
            nonce_hex,
            nonce_b64,
            nonce_b64url,
            output,
            ..
        } = args;
        debug!(
            "Loaded arguments: \n
            verification_server={verification_server}, \n
            ca_cert={ca_cert:?}, \n
            local_cache={local_cache:?}, \n
            evidence={evidence:?}, \n
            attester={attester:?}, \n
            ratsd_url={ratsd_url:?}, \n
            sim_claims={sim_claims:?}, \n
            sim_iak={sim_iak:?}, \n
            nonce_raw={nonce_raw:?}, \n
            nonce_hex={nonce_hex:?}, \n
            nonce_b64={nonce_b64:?}, \n
            nonce_b64url={nonce_b64url:?}, \n
            output={output:?}"
        );

        utils::check_output_file(&output, args.common.force)?;

        let nonce = if let Some(evidence_path) = evidence.as_ref() {
            // extract the challenge field from the provided CCA evidence token
            let data = fs::read(evidence_path)?;
            let token = decode_cca_token(&data)?;
            Nonce::Value(token.realm.challenge)
        } else if nonce_raw.is_some()
            || nonce_hex.is_some()
            || nonce_b64.is_some()
            || nonce_b64url.is_some()
        {
            // nonce from the provided nonce arguments
            let n = get_nonce(nonce_raw, nonce_hex, nonce_b64, nonce_b64url)?;
            Nonce::Value(n)
        } else {
            // generate a new random nonce of 64 bytes
            Nonce::Size(DEFAULT_NONCE_SIZE)
        };

        let ear = run_discovery_and_verify(
            &verification_server,
            ca_cert.as_ref(),
            local_cache.as_ref(),
            evidence.as_ref(),
            nonce,
            &attester,
            ratsd_url.as_deref(),
            sim_claims.as_ref(),
            sim_iak.as_ref(),
        )?;

        let parts: Vec<&str> = ear.split('.').collect();
        let ear_value: serde_json::Value =
            serde_json::from_slice(&utils::decode_base64_url_nopad(parts[1])?)?;

        debug!("Pretty print: {}", args.common.pretty);
        let ear_json = if args.common.pretty {
            serde_json::to_string_pretty(&ear_value)?
        } else {
            serde_json::to_string(&ear_value)?
        };
        info!("ear: {ear_json}");

        utils::write_output_to_file(&ear, &output)?;
        info!("EAR saved to: {:?}", output);

        Ok(())
    }

    // run discovery and establish ChallengeResponse Session to get the EAR from the verification server
    #[allow(clippy::too_many_arguments)]
    fn run_discovery_and_verify(
        verification_server: &str,
        ca_cert: Option<&PathBuf>,
        local_cache: Option<&PathBuf>,
        evidence: Option<&PathBuf>,
        nonce: Nonce,
        attester: &AttesterKind,
        ratsd_url: Option<&str>,
        sim_claims: Option<&PathBuf>,
        sim_iak: Option<&PathBuf>,
    ) -> Result<String> {
        let rt = Runtime::new()
            .map_err(|e| Error::custom(format!("could not create tokio runtime: {e}")))?;

        rt.block_on(async { let mut discovery_builder =
            DiscoveryBuilder::new().with_base_url(verification_server.to_string());

        let mut cr_builder = ChallengeResponseBuilder::new();

        if let Some(ca_cert) = ca_cert {
            discovery_builder = discovery_builder.with_root_certificate(ca_cert.clone());
            cr_builder = cr_builder.with_root_certificate(ca_cert.clone());
        }

        if let Some(local_cache) = local_cache {
            discovery_builder = discovery_builder.with_default_disk_cache(local_cache.clone());
        }

        let discoverer = discovery_builder.build()?;

        let verification_api = discoverer.get_verification_api().await?;

        if verification_api.service_state() != &ServiceState::Ready {
            return Err(Error::custom(
                "verification service is not ready"
            ));
        }

        let rel_path = verification_api.get_api_endpoint("newChallengeResponseSession");
        debug!("newChallengeResponseSession endpoint: {rel_path:?}");

        let Some(rel_path) = rel_path else {
            return Err(Error::custom(
                "missing newChallengeResponseSession endpoint in verification discovery document",
            ));
        };
        let apiendpoint = Url::parse(verification_server).map_err(|e| Error::custom(format!("invalid verification server URL: {e}")))?.join(&rel_path)?;
        debug!("newChallengeResponseSession url: {apiendpoint:?}");

        cr_builder = cr_builder.with_new_session_url(apiendpoint.to_string());

        let cr = cr_builder.build()?;

        let result = if let Some(evidence) = &evidence {
            // if evidence is provided, read the evidence from the file and echo it back to the verification server
            let token = fs::read(evidence)?;
            cr.run(nonce, evidence_echoer, token).await?
        } else {
            // if evidence is not provided, generate new evidence at runtime using attester and send it to the verification server
            cr.run(
                nonce,
                evidence_builder(
                    attester,
                    ratsd_url,
                    sim_claims,
                    sim_iak,
                ),
                Vec::new(),
            )
            .await?
        };

        let verifier_pkey = verification_api.ear_verification_key_as_string();

        let verifier_alg = verification_api.ear_verification_algorithm();

        // common of jsonwebkey::JsonWebKey algorithm and Ear algortihm is ES256
        let alg = match verifier_alg.as_str() {
            "ES256" => Algorithm::ES256,
            _ => {
                return Err(Error::InvalidValue {
                    value: verifier_alg.to_string(),
                    expected: "Ear signature-check only supports ES256 algorithm",
                });
            }
        };

        let _ = Ear::from_jwt_jwk(&result, alg, verifier_pkey.as_bytes())?;

        Ok(result)
        })
    }

    type EvidenceBuilderResult = std::result::Result<(Vec<u8>, String), veraison_apiclient::Error>;

    /// select_cca_media_type will check if the verification server supports the required media type for CCA evidence.
    fn select_cca_media_type(
        accept: &[String],
    ) -> std::result::Result<&'static str, veraison_apiclient::Error> {
        if accept.iter().any(|media_type| media_type == MEDIA_TYPE) {
            Ok(MEDIA_TYPE)
        } else {
            Err(veraison_apiclient::Error::CallbackError(format!(
                "verification service does not support required evidence media type {MEDIA_TYPE}; accepted: {accept:?}"
            )))
        }
    }

    /// evidence_echoer is an Evidence Callback function where same token bytes are echoed back
    /// to the verification server. Used when evidence is provided in cli argument.
    fn evidence_echoer(nonce: &[u8], accept: &[String], token: Vec<u8>) -> EvidenceBuilderResult {
        debug!("server challenge: {nonce:?}");
        debug!("acceptable media types: {accept:#?}");
        let media_type = select_cca_media_type(accept)?;
        Ok((token, media_type.to_string()))
    }

    /// evidence_builder is an Evidence Callback function where new evidence is generated at runtime
    /// using the provided attester and nonce. The generated evidence is returned to the verification server.
    fn evidence_builder(
        kind: &AttesterKind,
        ratsd_url: Option<&str>,
        sim_claims: Option<&PathBuf>,
        sim_iak: Option<&PathBuf>,
    ) -> impl FnOnce(&[u8], &[String], Vec<u8>) -> EvidenceBuilderResult {
        move |nonce: &[u8], accept: &[String], _token: Vec<u8>| -> EvidenceBuilderResult {
            let token_new = generate_evidence(kind, ratsd_url, sim_claims, sim_iak, nonce)
                .map_err(|e| veraison_apiclient::Error::CallbackError(e.to_string()))?;
            debug!("server challenge: {nonce:?}");
            debug!("acceptable media types: {accept:#?}");
            let media_type = select_cca_media_type(accept)?;
            Ok((token_new, media_type.to_string()))
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        use tokio::runtime::Runtime;
        use wiremock::{
            Mock, MockServer, ResponseTemplate,
            matchers::{method, path},
        };

        async fn start_mock_verification_server() -> MockServer {
            let server = MockServer::start().await;

            let discovery_document = fs::read("test/json/verificationdiscoverydoc.json").unwrap();

            Mock::given(method("GET"))
                .and(path("/.well-known/veraison/verification"))
                .respond_with(ResponseTemplate::new(200).set_body_raw(
                    discovery_document,
                    "application/vnd.veraison.discovery+json",
                ))
                .mount(&server)
                .await;

            let new_session = fs::read_to_string("test/json/chares-session-new.json").unwrap();

            Mock::given(method("POST"))
                .and(path("/challenge-response/v1/newSession"))
                .respond_with(
                    ResponseTemplate::new(201)
                        .insert_header("location", "session/1234")
                        .set_body_raw(
                            new_session,
                            "application/vnd.veraison.challenge-response-session+json",
                        ),
                )
                .mount(&server)
                .await;

            let complete_session =
                fs::read_to_string("test/json/chares-session-complete.json").unwrap();

            Mock::given(method("POST"))
                .and(path("/challenge-response/v1/session/1234"))
                .respond_with(ResponseTemplate::new(200).set_body_raw(
                    complete_session,
                    "application/vnd.veraison.challenge-response-session+json",
                ))
                .mount(&server)
                .await;

            debug!("Mock server running at {}", server.uri());

            server
        }

        #[test]
        fn test_verify_remote() {
            let server = Runtime::new()
                .unwrap()
                .block_on(async { start_mock_verification_server().await });

            let args = remote::Args {
                verification_server: server.uri(),
                ca_cert: None,
                local_cache: None,
                evidence: None,
                attester: AttesterKind::Sim,
                ratsd_url: None,
                sim_claims: None,
                sim_iak: None,
                nonce_raw: None,
                nonce_hex: None,
                nonce_b64: None,
                nonce_b64url: None,
                output: "ear.jwk".into(),
                common: CommonFlags {
                    pretty: true,
                    force: true,
                },
            };
            let result = remote::verify(args);
            println!("result: {:?}", result);
            assert!(result.is_ok());
        }

        #[test]
        fn test_verify_remote_with_evidence() {
            let server = Runtime::new()
                .unwrap()
                .block_on(async { start_mock_verification_server().await });

            let args = remote::Args {
                verification_server: server.uri(),
                ca_cert: None,
                local_cache: None,
                evidence: Some("test/cbor/ccatoken.cbor".into()),
                attester: AttesterKind::Ratsd,
                ratsd_url: None,
                sim_claims: None,
                sim_iak: None,
                nonce_raw: None,
                nonce_hex: None,
                nonce_b64: None,
                nonce_b64url: None,
                output: "ear.jwk".into(),
                common: CommonFlags {
                    pretty: true,
                    force: true,
                },
            };
            let result = remote::verify(args);
            println!("result: {:?}", result);
            assert!(result.is_ok());
        }
    }
}
