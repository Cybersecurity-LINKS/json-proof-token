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
    pub typ: Option<String>,
    /// Algorithm used for the JWP
    pub alg: ProofAlgorithm,
    /// ID for the key used for the JWP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// cid can be used similar to a cid in order to ensure externally resolve of claims
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cid: Option<String>,
    /// if you want you can put the claims directly into the header
    #[serde(skip_serializing_if = "Option::is_none")]
    pub claims: Option<Claims>
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct PresentationProtectedHeader {
    pub alg: ProofAlgorithm,
    /// ID for the key used for the JWP.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kid: Option<String>,
    /// Who have to receive the JPT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aud: Option<String>,
    /// For replay attacks
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>
}
