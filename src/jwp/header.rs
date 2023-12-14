// Copyright 2023 Fondazione LINKS

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

use crate::{jpt::claims::Claims, jpa::algs::ProofAlgorithm};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct IssuerProtectedHeader {
    /// JWP type (JPT)
    #[serde(skip_serializing_if = "Option::is_none")]
    typ: Option<String>,
    /// Algorithm used for the JWP
    alg: ProofAlgorithm,
    /// ID for the key used for the JWP.
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    /// cid can be used similar to a cid in order to ensure externally resolve of claims. FOr now this is not handled!
    #[serde(skip_serializing_if = "Option::is_none")]
    cid: Option<String>, 
    /// if you want you can put the claims directly into the header
    #[serde(skip_serializing_if = "Option::is_none")]
    claims: Option<Claims>
}


impl IssuerProtectedHeader {

    pub fn new(alg: ProofAlgorithm) -> Self {
        Self{
            typ: Some("JPT".to_owned()),
            alg,
            kid: None,
            cid: None,
            claims: None
        }
    }


    // Getter for alg
    pub fn alg(&self) -> ProofAlgorithm {
        self.alg
    }

    // Getter for typ
    pub fn typ(&self) -> Option<&String> {
        self.typ.as_ref()
    }

    // Setter for typ
    pub fn set_typ(&mut self, value: Option<String>) {
        self.typ = value;
    }

    // Getter for kid
    pub fn kid(&self) -> Option<&String> {
        self.kid.as_ref()
    }

    // Setter for kid
    pub fn set_kid(&mut self, value: Option<String>) {
        self.kid = value;
    }

    // Getter for cid
    pub fn cid(&self) -> Option<&String> {
        self.cid.as_ref()
    }

    // Setter for cid
    pub fn set_cid(&mut self, value: Option<String>) {
        self.cid = value;
    }

    // Getter for claims
    pub fn claims(&self) -> Option<&Claims> {
        self.claims.as_ref()
    }

    // Setter for claims
    pub(crate) fn set_claims(&mut self, value: Option<Claims>) {
        self.claims = value;
    }
}


#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PresentationProtectedHeader {
    alg: ProofAlgorithm,
    /// ID for the key used for the JWP.
    #[serde(skip_serializing_if = "Option::is_none")]
    kid: Option<String>,
    /// Who have to receive the JPT.
    #[serde(skip_serializing_if = "Option::is_none")]
    aud: Option<String>,
    /// For replay attacks
    #[serde(skip_serializing_if = "Option::is_none")]
    nonce: Option<String>
}

impl PresentationProtectedHeader {

    pub fn new(alg: ProofAlgorithm) -> Self {
        Self {
            alg,
            kid: None,
            aud: None,
            nonce: None,
        }
    }


    // Getter for alg
    pub fn alg(&self) -> ProofAlgorithm {
        self.alg
    }

    // Getter for kid
    pub fn kid(&self) -> Option<&String> {
        self.kid.as_ref()
    }

    // Setter for kid
    pub fn set_kid(&mut self, value: Option<String>) {
        self.kid = value;
    }

    // Getter for aud
    pub fn aud(&self) -> Option<&String> {
        self.aud.as_ref()
    }

    // Setter for aud
    pub fn set_aud(&mut self, value: Option<String>) {
        self.aud = value;
    }

    // Getter for nonce
    pub fn nonce(&self) -> Option<&String> {
        self.nonce.as_ref()
    }

    // Setter for nonce
    pub fn set_nonce(&mut self, value: Option<String>) {
        self.nonce = value;
    }
}

