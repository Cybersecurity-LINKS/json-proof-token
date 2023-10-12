use serde::{Deserialize, Serialize};

use crate::{jpt::claims::{JptClaims, Claims}, jpa::algs::ProofAlgorithm};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct IssuerProtectedHeader {
    /// JWP type (JPT)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,
    /// Algorithm used for the JWP
    pub alg: ProofAlgorithm,
    /// Who issued the JWP
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// cid can be used similar to a kid in order to ensure externally resolve of claims
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    /// if you want you can put the claims directly into the header
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Claims>
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PresentationProtectedHeader {
    /// Who have to receive the JPT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// For replay attacks
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>
}