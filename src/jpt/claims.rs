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
use serde::{Deserialize, Serialize, Serializer};
use serde_json::{Value, value::Index, json};


use crate::flattening::json_value_flattening;

use super::payloads::Payloads;

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Claims (pub Vec<String>);

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
    /// Issue time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub iat: Option<i64>,
    /// Unique ID for the JPT.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jti: Option<String>,
    // Other claims (age, name, surname, ...)
    // #[serde(flatten, skip_serializing_if = "Option::is_none")]
    // pub custom: Option<Value>
    #[serde(flatten)]
    pub custom: IndexMap<String, Value>
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
            custom: IndexMap::new() }
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
            self.custom.insert(claim.unwrap_or("").to_string(), serde_value);

        } else {
            if flattened {
                let v = match claim {
                    Some(c) => json!({c: serde_value}),
                    None => serde_value,
                };
                self.custom.extend(json_value_flattening(v));
            } else {
                self.custom.insert(claim.unwrap_or("").to_string(), serde_value);
            }
        };
        
    }


    /// Extracts claims and payloads into separate vectors.
    pub fn get_claims_and_payloads(&self) -> (Claims, Payloads){
        let jptclaims_json_value = serde_json::to_value(self).unwrap();
        let claims_payloads_pairs = jptclaims_json_value.as_object().unwrap().to_owned();
        
        let (keys, values): (Vec<String>, Vec<Value>) = claims_payloads_pairs.to_owned().into_iter().unzip();

        (Claims(keys), Payloads::new_from_values(values))
        
    }


    pub fn from_claims_and_payloads(claims: Claims, payloads: Payloads) {
        let zip: Vec<(String, Value)> = zip(claims.0, payloads.get_values()).collect();

        //TODO: continue from this
        todo!()
        
    }


    // pub fn from_attributes(attributes: BTreeMap<String, String>) -> Result<JptClaims, serde_json::Error> {
    //     let mut claims = JptClaims::default();

    //     for (key, value) in attributes {
    //         match key.as_str() {
    //             "sub" => claims.sub = Some(value),
    //             "exp" => claims.exp = Some(value.parse::<i64>().unwrap_or(0)), // Handle parsing errors
    //             "nbf" => claims.nbf = Some(value.parse::<i64>().unwrap_or(0)), // Handle parsing errors
    //             "iat" => claims.iat = Some(value.parse::<i64>().unwrap_or(0)), // Handle parsing errors
    //             "jti" => claims.jti = Some(value),
    //             _ => {
    //                 // Parse custom claims as JSON strings
    //                 if claims.custom.is_none() {
    //                     claims.custom = Some(Value::Object(Default::default()));
    //                 }

    //                 if let Some(custom) = claims.custom.as_mut() {
    //                     if let Value::Object(custom_object) = custom {
    //                         custom_object.insert(key, serde_json::from_str(&value)?);
    //                     }
    //                 }
    //             }
    //         }
    //     }

    //     Ok(claims)
    // }
  
}