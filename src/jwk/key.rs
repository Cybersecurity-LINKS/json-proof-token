use serde::{Deserialize, Serialize};

use super::alg_parameters::{JwkAlgorithmParameters, Algorithm};



/// JWK parameters defined at https://datatracker.ietf.org/doc/html/rfc7517#section-4
#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
pub struct Jwk {
    /// ID of the key
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub kid: Option<String>,

    /// The intended use of the public key
    #[serde(rename = "use", skip_serializing_if = "Option::is_none", default)]
    pub pk_use: Option<PKUse>,

    /// The "key_ops" (key operations) parameter identifies the operation(s) for which the key is intended to be used
    
    /// The "use" and "key_ops" JWK members SHOULD NOT be used together;
    /// however, if both are used, the information they convey MUST be
    /// consistent.  Applications should specify which of these members they
    /// use, if either is to be used by the application.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub key_ops: Option<Vec<KeyOps>>,

    /// The algorithm intended to be used
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub alg: Option<Algorithm>,

    /// X.509 Public key cerfificate URL. 
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5u: Option<String>,

    /// X.509 public key certificate chain.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5c: Option<Vec<String>>,

    /// X.509 Certificate thumbprint.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x5t: Option<String>,

    //Key parameters based on the algorithm
    #[serde(flatten)]
    pub key_params: JwkAlgorithmParameters,
    
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum KeyOps {}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum PKUse {}
