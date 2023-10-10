use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::encoding::base64url_encode_serializable;


#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Payloads (pub Vec<String>);

impl Payloads {
    pub fn from_values(values: Vec<Value>) -> Self {
        Self(values.iter().map(|v| base64url_encode_serializable(v)).collect())
    }
}