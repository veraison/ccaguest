// Copyright 2026 Contributors to the Veraison project.
// SPDX-License-Identifier: Apache-2.0

use coserv_rs::coserv::corim_rs::{CryptoKeyTypeChoice, EnvironmentMap};
use cover::{Ect, Policy, Scheme, cca::CcaScheme, result::Result};
use log::debug;
use std::{fs, path::PathBuf};

/// [CcaCustomScheme] is a wrapper around [cover::cca::CcaScheme] with custom policy.
pub struct CcaCustomScheme {
    /// custom policy of [cover::Policy] type
    custom_policy: Policy,
    /// [cover::cca::CcaScheme] struct
    inner: CcaScheme,
}

impl CcaCustomScheme {
    /// Creates a new [CcaCustomScheme] with custom policy read from provided path.
    pub fn new(path: &PathBuf) -> Result<Self> {
        debug!("creating new CcaCustomScheme using {:?} policy", path);
        let text = fs::read_to_string(path)?;
        let file_name = match path.file_stem() {
            None => "custom".to_string(),
            Some(f) => f.to_string_lossy().to_string() + "-custom",
        };
        let policy = Policy {
            id: file_name,
            path: path.to_string_lossy().into_owned(),
            text,
        };
        let inner = CcaScheme::new();
        Ok(CcaCustomScheme {
            custom_policy: policy,
            inner,
        })
    }
}

impl Scheme for CcaCustomScheme {
    fn name(&self) -> String {
        "custom cca scheme".to_string()
    }

    fn profile(&self) -> String {
        self.inner.profile()
    }

    fn match_evidence(&self, evidence: &[u8]) -> bool {
        self.inner.match_evidence(evidence)
    }

    fn get_trust_anchor_id<'a>(&self, evidence: &[u8]) -> Result<EnvironmentMap<'a>> {
        self.inner.get_trust_anchor_id(evidence)
    }

    fn validate_and_parse_evidence<'a>(
        &self,
        evidence: &[u8],
        trust_anchor: &CryptoKeyTypeChoice<'a>,
    ) -> Result<Vec<Ect<'a>>> {
        self.inner
            .validate_and_parse_evidence(evidence, trust_anchor)
    }

    /// get_policies returns the list of default and custom policy.
    fn get_policies(&self) -> Vec<Policy> {
        let mut policies = self.inner.get_policies();
        policies.push(self.custom_policy.clone());
        policies
    }
}
