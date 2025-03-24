// Copyright 2025 Fondazione LINKS

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use serde::{Deserialize, Serialize};

use crate::{
    jpa::algs::{PresentationProofAlgorithm, ProofAlgorithm},
    jpt::claims::Claims, jwk::key::Jwk,
};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
/// JWP Issuer Protected Header, defined in https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-proof-08#name-issuer-protected-header
pub struct IssuerProtectedHeader {
    /// JWP type (JPT)
    #[serde(skip_serializing_if = "Option::is_none")]
    typ: Option<String>,
    /// Algorithm used for the JWP
    alg: ProofAlgorithm,
    /// ID for the key used for the JWP.
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    /// ClaimsID, identifier for a set of claim names without explicitly listing 
    /// them in order to ensure externally resolve of claims. Application dependent.
    #[serde(skip_serializing_if = "Option::is_none")]
    cid: Option<String>,
    /// if you want you can put the claims directly into the header
    #[serde(skip_serializing_if = "Option::is_none")]
    claims: Option<Claims>,
    /// Critical Header Parameter indicates that extensions to the json-web-proof specification and/or json-proof-algorithms 
    /// are being used that MUST be understood and processed
    /// see https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-proof-08#name-crit-critical-header-parame
    #[serde(skip_serializing_if = "Option::is_none")]
    crit: Option<Vec<String>>,
    /// Issuer Header Parameter identifies the principal that issued the JWP.
    /// The processing of this claim is generally application specific.
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    /// Proof Key represents the public key used by the issuer for proof of possession within certain algorithms.
    /// This is an ephemeral key that MUST be unique for each issued JWP
    /// See https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-proof-08#name-proof_key-proof-key-header-
    #[serde(skip_serializing_if = "Option::is_none")]
    proof_key: Option<Jwk>,
}

impl IssuerProtectedHeader {
    /// Constructor for IssuerProtectedHeader, sets the ProofAlgorithm and the typ as JPT
    pub fn new(alg: ProofAlgorithm) -> Self {
        Self {
            typ: Some("JPT".to_owned()),
            alg,
            kid: None,
            cid: None,
            claims: None,
            crit: None,
            iss: None,
            proof_key: None,
        }
    }

    /// Getter for alg
    pub fn alg(&self) -> ProofAlgorithm {
        self.alg
    }

    /// Getter for typ
    pub fn typ(&self) -> Option<&String> {
        self.typ.as_ref()
    }

    /// Setter for typ
    pub fn set_typ(&mut self, value: Option<String>) {
        self.typ = value;
    }

    /// Getter for kid
    pub fn kid(&self) -> Option<&String> {
        self.kid.as_ref()
    }

    /// Setter for kid
    pub fn set_kid(&mut self, value: Option<String>) {
        self.kid = value;
    }

    /// Getter for cid
    pub fn cid(&self) -> Option<&String> {
        self.cid.as_ref()
    }

    /// Setter for cid
    pub fn set_cid(&mut self, value: Option<String>) {
        self.cid = value;
    }

    /// Getter for claims
    pub fn claims(&self) -> Option<&Claims> {
        self.claims.as_ref()
    }

    /// Setter for claims
    pub(crate) fn set_claims(&mut self, value: Option<Claims>) {
        self.claims = value;
    }

    /// Getter for crit
    pub fn crit(&self) -> Option<&Vec<String>> {
        self.crit.as_ref()
    }

    /// Setter for claims
    pub fn set_crit(&mut self, value: Option<Vec<String>>) {
        self.crit = value;
    }

    /// Getter for iss
    pub fn iss(&self) -> Option<&String> {
        self.iss.as_ref()
    }

    /// Setter for iss
    pub fn set_iss(&mut self, value: Option<String>) {
        self.iss = value;
    }

    /// Getter for proof_key
    pub fn proof_key(&self) -> Option<Jwk> {
        self.proof_key.clone()
    }

    /// Setter for proof_key
    pub fn set_proof_key(&mut self, value: Option<Jwk>) {
        self.proof_key = value;
    }
    
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PresentationProtectedHeader {
    alg: PresentationProofAlgorithm,
    /// ID for the key used for the JWP.
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    /// Audience Header Parameter identifies the recipients that the JWP is intended, generally application specific.
    /// See https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-proof-08#name-aud-audience-header-paramet.
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    /// For replay attacks
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>,
    /// JWP type (JPT)
    #[serde(skip_serializing_if = "Option::is_none")]
    typ: Option<String>,
    /// Critical Header Parameter indicates that extensions to the json-web-proof specification and/or json-proof-algorithms 
    /// are being used that MUST be understood and processed
    /// see https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-proof-08#name-crit-critical-header-parame
    #[serde(skip_serializing_if = "Option::is_none")]
    crit: Option<Vec<String>>,
    /// Issuer Header Parameter identifies the principal that issued the JWP.
    /// The processing of this claim is generally application specific.
    #[serde(skip_serializing_if = "Option::is_none")]
    iss: Option<String>,
    /// Presentation Key represents the public key is used by the holder for proof of possession and integrity
    /// protection of the presented protected header.
    /// See https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-proof-08#name-presentation_key-presentati
    #[serde(skip_serializing_if = "Option::is_none")]
    presentation_key: Option<Jwk>,
}

impl PresentationProtectedHeader {
    /// Constructor for PresentationProtectedHeader, sets the PresentationProofAlgorithm 
    pub fn new(alg: PresentationProofAlgorithm) -> Self {
        Self {
            alg,
            kid: None,
            aud: None,
            nonce: None,
            typ: None,
            crit: None,
            iss: None,
            presentation_key: None,
        }
    }

    /// Getter for alg
    pub fn alg(&self) -> PresentationProofAlgorithm {
        self.alg
    }

    /// Getter for kid
    pub fn kid(&self) -> Option<&String> {
        self.kid.as_ref()
    }

    /// Setter for kid
    pub fn set_kid(&mut self, value: Option<String>) {
        self.kid = value;
    }

    /// Getter for aud
    pub fn aud(&self) -> Option<&String> {
        self.aud.as_ref()
    }

    /// Setter for aud
    pub fn set_aud(&mut self, value: Option<String>) {
        self.aud = value;
    }

    /// Getter for nonce
    pub fn nonce(&self) -> Option<&String> {
        self.nonce.as_ref()
    }

    /// Setter for nonce
    pub fn set_nonce(&mut self, value: Option<String>) {
        self.nonce = value;
    }

    /// Getter for typ
    pub fn typ(&self) -> Option<&String> {
        self.typ.as_ref()
    }

    /// Setter for typ
    pub fn set_typ(&mut self, value: Option<String>) {
        self.typ = value;
    }

    /// Getter for crit
    pub fn crit(&self) -> Option<&Vec<String>> {
        self.crit.as_ref()
    }

    /// Setter for claims
    pub fn set_crit(&mut self, value: Option<Vec<String>>) {
        self.crit = value;
    }

    /// Getter for iss
    pub fn iss(&self) -> Option<&String> {
        self.iss.as_ref()
    }

    /// Setter for iss
    pub fn set_iss(&mut self, value: Option<String>) {
        self.iss = value;
    }

    /// Getter for presentation_key
    pub fn presentation_key(&self) -> Option<Jwk> {
        self.presentation_key.clone()
    }

    /// Setter for presentation_key
    pub fn set_presentation_key(&mut self, value: Option<Jwk>) {
        self.presentation_key = value;
    }

}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn test_default_issuer_protected_header() {
        let header = IssuerProtectedHeader::new(ProofAlgorithm::BBS);
        assert_eq!(header.alg(), ProofAlgorithm::BBS);
        assert_eq!(header.typ(), Some(&"JPT".to_owned()));
        assert_eq!(header.kid(), None);
        assert_eq!(header.cid(), None);
        assert_eq!(header.claims(), None);
        assert_eq!(header.crit(), None);
        assert_eq!(header.iss(), None);
        assert_eq!(header.proof_key(), None);
    }

    #[test]
    fn test_custom_issuer_protected_header(){
        let json = json!({
            "kid": "HjfcpyjuZQ-O8Ye2hQnNbT9RbbnrobptdnExR0DUjU8",
            "alg": "BBS",
            "typ": "JPT",
            "iss": "example.com",
            "cid": "example.com/cid/123",
            "claims": [
                "iat",
                "exp",
                "family_name",
                "given_name",
                "email",
                "address",
                "age_over_21"
            ],
            "crit": [
                "critical_extension_1",
                "critical_extension_2",
            ],
            "proof_key" : {
                "kty": "EC",
                "crv": "BLS12381G2",
                "x": "AizYfy-snuLWBAQjzm5UJcmXkNe4DPVbcqFha7i7hgmpiDgGHVUdqqM8YWmWkzi-DBSTXPozzlvnB1TZXcgXtYPla9M1iyK3evsD3Eoyo3ClR1_I_Pfmlk_signHOz9i",
                "y": "A8PoKJou9-4t93kYDlIX_BGMgAqjIaZIW5TRQwusD4lDhcmSZy9hY5Sl2NxERhA8ERq2NLklV6dethvprgZ3hKfzrjU97MtkcY2ql-390o08o_C475nIAXqtgDqZwg-X",
                "d": "UFjZc6H5vhHAmPcchdlRLnfNKmSCbnqDylT3aKZYSW4"
            }
        });
        let claims: Claims = serde_json::from_value(json!(["iat", "exp", "family_name", "given_name", "email", "address", "age_over_21"]))
            .expect("Failed to deserialize Claims");
        let jwk: Jwk = serde_json::from_value(json!({
            "kty": "EC",
            "crv": "BLS12381G2",
            "x": "AizYfy-snuLWBAQjzm5UJcmXkNe4DPVbcqFha7i7hgmpiDgGHVUdqqM8YWmWkzi-DBSTXPozzlvnB1TZXcgXtYPla9M1iyK3evsD3Eoyo3ClR1_I_Pfmlk_signHOz9i",
            "y": "A8PoKJou9-4t93kYDlIX_BGMgAqjIaZIW5TRQwusD4lDhcmSZy9hY5Sl2NxERhA8ERq2NLklV6dethvprgZ3hKfzrjU97MtkcY2ql-390o08o_C475nIAXqtgDqZwg-X",
            "d": "UFjZc6H5vhHAmPcchdlRLnfNKmSCbnqDylT3aKZYSW4"
        })).expect("Failed to deserialize Jwk");
        let header: IssuerProtectedHeader = serde_json::from_value(json).expect("Failed to deserialize IssuerProtectedHeader");
        assert_eq!(header.alg(), ProofAlgorithm::BBS);
        assert_eq!(header.typ(), Some(&"JPT".to_owned()));
        assert_eq!(header.kid(), Some(&"HjfcpyjuZQ-O8Ye2hQnNbT9RbbnrobptdnExR0DUjU8".to_owned()));
        assert_eq!(header.cid(), Some(&"example.com/cid/123".to_owned()));
        assert_eq!(header.claims(), Some(&claims));
        assert_eq!(header.crit(), Some(&vec!["critical_extension_1".to_owned(), "critical_extension_2".to_owned()]));
        assert_eq!(header.proof_key(), Some(jwk));
        assert_eq!(header.iss(), Some(&"example.com".to_owned()));

    }

    #[test]
    fn test_default_presentation_protected_header() {
        let header = PresentationProtectedHeader::new(PresentationProofAlgorithm::BBS_SHAKE256);
        assert_eq!(header.alg(), PresentationProofAlgorithm::BBS_SHAKE256);
        assert_eq!(header.kid(), None);
        assert_eq!(header.aud(), None);
        assert_eq!(header.nonce(), None);
        assert_eq!(header.typ(), None);
        assert_eq!(header.crit(), None);
        assert_eq!(header.iss(), None);
        assert_eq!(header.presentation_key(), None);
    }

    #[test]
    fn test_custom_presentation_protected_header(){
        let json = json!({
            "kid": "HjfcpyjuZQ-O8Ye2hQnNbT9RbbnrobptdnExR0DUjU8",
            "alg": "BBS",
            "typ": "JPT",
            "iss": "example.com",
            "aud": "audience_example",
            "crit": [
                "critical_extension_1",
                "critical_extension_2",
            ],
            "presentation_key" : {
                "kty": "EC",
                "crv": "BLS12381G2",
                "x": "AizYfy-snuLWBAQjzm5UJcmXkNe4DPVbcqFha7i7hgmpiDgGHVUdqqM8YWmWkzi-DBSTXPozzlvnB1TZXcgXtYPla9M1iyK3evsD3Eoyo3ClR1_I_Pfmlk_signHOz9i",
                "y": "A8PoKJou9-4t93kYDlIX_BGMgAqjIaZIW5TRQwusD4lDhcmSZy9hY5Sl2NxERhA8ERq2NLklV6dethvprgZ3hKfzrjU97MtkcY2ql-390o08o_C475nIAXqtgDqZwg-X",
                "d": "UFjZc6H5vhHAmPcchdlRLnfNKmSCbnqDylT3aKZYSW4"
            },
            "nonce": "wrmBRkKtXjQ"
        });

        let jwk: Jwk = serde_json::from_value(json!({
            "kty": "EC",
            "crv": "BLS12381G2",
            "x": "AizYfy-snuLWBAQjzm5UJcmXkNe4DPVbcqFha7i7hgmpiDgGHVUdqqM8YWmWkzi-DBSTXPozzlvnB1TZXcgXtYPla9M1iyK3evsD3Eoyo3ClR1_I_Pfmlk_signHOz9i",
            "y": "A8PoKJou9-4t93kYDlIX_BGMgAqjIaZIW5TRQwusD4lDhcmSZy9hY5Sl2NxERhA8ERq2NLklV6dethvprgZ3hKfzrjU97MtkcY2ql-390o08o_C475nIAXqtgDqZwg-X",
            "d": "UFjZc6H5vhHAmPcchdlRLnfNKmSCbnqDylT3aKZYSW4"
        })).expect("Failed to deserialize Jwk");
        let header: PresentationProtectedHeader = serde_json::from_value(json).expect("Failed to deserialize IssuerProtectedHeader");
        assert_eq!(header.alg(), PresentationProofAlgorithm::BBS);
        assert_eq!(header.typ(), Some(&"JPT".to_owned()));
        assert_eq!(header.kid(), Some(&"HjfcpyjuZQ-O8Ye2hQnNbT9RbbnrobptdnExR0DUjU8".to_owned()));
        assert_eq!(header.crit(), Some(&vec!["critical_extension_1".to_owned(), "critical_extension_2".to_owned()]));
        assert_eq!(header.presentation_key(), Some(jwk));
        assert_eq!(header.iss(), Some(&"example.com".to_owned()));
        assert_eq!(header.aud(), Some(&"audience_example".to_owned()));
        assert_eq!(header.nonce(), Some(&"wrmBRkKtXjQ".to_owned()));

    }

    #[test]
    fn test_set_issuer_protected_header() {
        let mut  header = IssuerProtectedHeader::new(ProofAlgorithm::BBS);
        let claims: Claims = serde_json::from_value(json!(["iat", "exp", "family_name", "given_name", "email", "address", "age_over_21"]))
            .expect("Failed to deserialize Claims");
        header.set_kid(Some("HjfcpyjuZQ-O8Ye2hQnNbT9RbbnrobptdnExR0DUjU8".to_owned()));
        header.set_cid(Some("example.com/cid/123".to_owned()));
        header.set_claims(Some(claims));
        header.set_crit(Some(vec!["critical_extension_1".to_owned(), "critical_extension_2".to_owned()]));
        header.set_iss(Some("example.com".to_owned()));
        
        let json = json!({
            "kid": "HjfcpyjuZQ-O8Ye2hQnNbT9RbbnrobptdnExR0DUjU8",
            "alg": "BBS",
            "typ": "JPT",
            "iss": "example.com",
            "cid": "example.com/cid/123",
            "claims": [
                "iat",
                "exp",
                "family_name",
                "given_name",
                "email",
                "address",
                "age_over_21"
            ],
            "crit": [
                "critical_extension_1",
                "critical_extension_2",
            ],
        });

       let header_json: IssuerProtectedHeader = serde_json::from_value(json).expect("Failed to deserialize IssuerProtectedHeader");
       assert_eq!(header, header_json);

    }
    #[test]
    fn test_set_presentation_protected_header() {
        let mut  header = PresentationProtectedHeader::new(PresentationProofAlgorithm::BBS_SHAKE256);

        header.set_kid(Some("HjfcpyjuZQ-O8Ye2hQnNbT9RbbnrobptdnExR0DUjU8".to_owned()));
        header.set_crit(Some(vec!["critical_extension_1".to_owned(), "critical_extension_2".to_owned()]));
        header.set_iss(Some("example.com".to_owned()));
        header.set_aud(Some("audience_example".to_owned()));
        header.set_nonce(Some("wrmBRkKtXjQ".to_owned()));
        header.set_typ(Some("JPT".to_owned()));
        let json = json!({
            "kid": "HjfcpyjuZQ-O8Ye2hQnNbT9RbbnrobptdnExR0DUjU8",
            "alg": "BBS-SHAKE256",
            "typ": "JPT",
            "iss": "example.com",
            "aud": "audience_example",
            "crit": [
                "critical_extension_1",
                "critical_extension_2",
            ],
            "nonce": "wrmBRkKtXjQ"
        });

       let header_json: PresentationProtectedHeader = serde_json::from_value(json).expect("Failed to deserialize PresentationProtectedHeader");
       assert_eq!(header, header_json);

    }

}