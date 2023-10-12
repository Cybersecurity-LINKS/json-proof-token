use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::encoding::base64url_encode_serializable;

///TODO: Not clear what to do with this information 
/// (https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-proof-token#name-payloads)
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum PayloadType{
    Disclosed,
    Undisclosed,
    ProofMethods
}


#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Payloads (pub Vec<(String, PayloadType)>);

impl Payloads {
    pub fn new_from_values(values: Vec<Value>) -> Self {
        Self(values.iter().map(|v| (base64url_encode_serializable(v), PayloadType::Disclosed)).collect())
    }
}