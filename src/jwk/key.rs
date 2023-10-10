use serde::{Deserialize, Serialize};


#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Jwk {
    #[serde(rename = "kid", skip_serializing_if = "Option::is_none", default)]
    pub key_id: Option<String>,
}

