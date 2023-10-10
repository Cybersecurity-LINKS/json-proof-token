use serde::{Deserialize, Serialize};

use super::key::Jwk;

/// JSON Web Key Set (https://tools.ietf.org/html/rfc7517#section-5)
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct JwkSet {
  pub keys: Vec<Jwk>,
}


impl JwkSet {
    pub fn find(&self, kid: &str) -> Option<&Jwk> {
        self.keys
            .iter()
            .find(|jwk| jwk.kid.is_some() && jwk.kid.as_ref().unwrap() == kid)
    }
}