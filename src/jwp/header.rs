use serde::{Deserialize, Serialize};

use crate::jpt::claims::JptClaims;

use super::algs::JwpAlgorithm;

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct IssuerProtectedHeader {
    /// JWP type (JPT)
    #[serde(skip_serializing_if = "Option::is_none")]
    typ: Option<String>,
    /// Algorithm used for the JWP
    alg: JwpAlgorithm,
    /// Who issued the JWP
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    /// cid can be used similar to a kid in order to ensure externally resolve of claims
    #[serde(skip_serializing_if = "Option::is_none")]
    cid: Option<String>,
    /// if you want you can put the claims directly into the header
    #[serde(skip_serializing_if = "Option::is_none")]
    claims: Option<JptClaims>
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct PresentationProtectedHeader {
    /// Who have to receive the JPT.
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    /// For replay attacks
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>
}