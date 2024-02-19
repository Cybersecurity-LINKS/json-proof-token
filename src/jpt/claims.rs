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

use std::iter::zip;

use indexmap::IndexMap;
use json_unflattening::{flattening::flatten, unflattening::unflatten};
use serde::{Deserialize, Serialize};
use serde_json::{json, value::Index, Map, Value};

use super::payloads::Payloads;

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Claims(pub Vec<String>);

impl Claims {
    pub fn get_claim_index(&self, name: String) -> Option<usize> {
        self.0.iter().position(|x| *x == name)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct CustomValue {
    value: Value,
    #[serde(skip_serializing)]
    flattening: bool,
}

/** These claims are taken from the JWT RFC (https://tools.ietf.org/html/rfc7519)
 * making the hypothesis that in the future will be used also for the JPTs **/

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct JptClaims {
    /** Apparently the "aud" that in JWT was a claim, now should be an presentation protected header parameter
     * (https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-proof#name-presentation-protected-head) **/
    /// Who issued the JWP
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iss: Option<String>,
    /// Subject of the JPT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sub: Option<String>,
    /// Expiration time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exp: Option<i64>,
    /// Time before which the JPT MUST NOT be accepted
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nbf: Option<i64>,
    /// Issuance time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// Unique ID for the JPT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    /// Other custom claims (age, name, surname, Verifiable Credential, ...)
    #[serde(flatten)]
    pub custom: IndexMap<String, Value>,
}

impl JptClaims {
    pub fn new() -> Self {
        Self {
            iss: None,
            sub: None,
            exp: None,
            nbf: None,
            iat: None,
            jti: None,
            custom: IndexMap::new(),
        }
    }

    pub fn set_iss(&mut self, value: String) {
        self.iss = Some(value);
    }

    pub fn set_sub(&mut self, value: String) {
        self.sub = Some(value);
    }

    pub fn set_exp(&mut self, value: i64) {
        self.exp = Some(value);
    }

    pub fn set_nbf(&mut self, value: i64) {
        self.nbf = Some(value);
    }

    pub fn set_iat(&mut self, value: i64) {
        self.iat = Some(value);
    }

    pub fn set_jti(&mut self, value: String) {
        self.jti = Some(value);
    }

    pub fn set_claim<T: Serialize>(&mut self, claim: Option<&str>, value: T, flattened: bool) {
        let serde_value = serde_json::to_value(value).unwrap();
        if !serde_value.is_object() {
            self.custom
                .insert(claim.unwrap_or("").to_string(), serde_value);
        } else {
            if flattened {
                let v = match claim {
                    Some(c) => json!({c: serde_value}),
                    None => serde_value,
                };
                self.custom.extend(flatten(&v).unwrap());
            } else {
                self.custom
                    .insert(claim.unwrap_or("").to_string(), serde_value);
            }
        };
    }

    pub fn get_claim(&self, claim: &str) -> Option<&Value> {
        self.custom.get(claim)
    }

    pub fn update_claim_and_return_older(&mut self, claim: &str, value: Value) -> Option<Value> {
        self.custom.insert(claim.to_owned(), value)
    }

    /// Extracts claims and payloads into separate vectors.
    pub fn get_claims_and_payloads(&self) -> (Claims, Payloads) {
        let jptclaims_json_value = serde_json::to_value(self).unwrap();

        let claims_payloads_pairs = jptclaims_json_value.as_object().unwrap().to_owned();

        let (keys, values): (Vec<String>, Vec<Value>) =
            claims_payloads_pairs.to_owned().into_iter().unzip();

        (Claims(keys), Payloads::new_from_values(values))
    }

    /// Reconstruct JptClaims from Claims and Payloads
    pub fn from_claims_and_payloads(claims: &Claims, payloads: &Payloads) -> Self {
        let zip: Map<String, Value> = zip(claims.0.clone(), payloads.get_values()).collect();
        let unflat = unflatten(&zip).unwrap();
        let jpt_claims: Self = serde_json::from_value(unflat).unwrap();

        jpt_claims
    }
}
