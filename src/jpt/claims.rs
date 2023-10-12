use std::collections::{HashMap, BTreeMap};
use flatten_json_object::{Flattener, ArrayFormatting};
use serde::{Deserialize, Serialize};
use serde_json::{Value, Map};

use crate::encoding::base64url_encode_serializable;

use super::payloads::Payloads;

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Claims (pub Vec<String>);

/** These claims are taken from the JWT RFC (https://tools.ietf.org/html/rfc7519) 
 * making the hypothesis that in the future will be used also for the JPTs **/

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct JptClaims {

    /// Apparently the "iss" that in JWT was a claim, now should be an issuer protected header parameter 
    /** Apparently the "aud" that in JWT was a claim, now should be an presentation protected header parameter 
      * (https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-web-proof#name-presentation-protected-head) **/
    
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
    /// Other claims (age, name, surname, ...)
    #[serde(flatten, skip_serializing_if = "Option::is_none")]
    // custom: Option<Vec<String>>
    pub custom: Option<Value>
}


impl JptClaims {

    /// Extracts claims and payloads into separate vectors.
    pub fn get_claims_and_payloads(&self) -> (Claims, Payloads){

        let jptclaims_json_value = serde_json::to_value(self).unwrap();
            
        let flattened = Flattener::new()
        .set_key_separator(".")
        .set_array_formatting(ArrayFormatting::Surrounded {
            start: "[".to_string(),
            end: "]".to_string()
        })
        .set_preserve_empty_arrays(false)
        .set_preserve_empty_objects(false)
        .flatten(&jptclaims_json_value).unwrap();

        println!("flatted: {}", flattened);

        
        let claim_payload_pairs: HashMap<String, Value> = serde_json::from_value::<HashMap<String, Value>>(flattened.clone()).unwrap();

        let (keys, values): (Vec<String>, Vec<Value>) = claim_payload_pairs.into_iter().unzip();

        (Claims(keys), Payloads::from_values(values))
        
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