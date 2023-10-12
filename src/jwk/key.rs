use std::error::Error;

use serde::{Deserialize, Serialize};

use crate::errors::MyError;

use super::{alg_parameters::{JwkAlgorithmParameters, Algorithm}, utils::check_alg_curve_compatibility};



/// JWK parameters defined at https://datatracker.ietf.org/doc/html/rfc7517#section-4
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
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

impl Jwk {
    pub fn new(
        kid: Option<String>,
        pk_use: Option<PKUse>,
        key_ops: Option<Vec<KeyOps>>,
        alg: Option<Algorithm>,
        x5u: Option<String>,
        x5c: Option<Vec<String>>,
        x5t: Option<String>,
        key_params: JwkAlgorithmParameters,
    ) -> Result<Self, Box<MyError>>{

        let mut check = true;
        match &key_params {
            JwkAlgorithmParameters::OctetKeyPair(params) => {
                if let Some(alg) = alg {
                    check =  check_alg_curve_compatibility(alg, params.crv.clone());
                }
            },
        }
        
        match check {
            true => {
                Ok(Jwk{
                    kid,
                    pk_use,
                    key_ops,
                    alg,
                    x5u,
                    x5c,
                    x5t,
                    key_params
                })
            }
            false => {
                Err(Box::new(MyError("Algorithm and Key params compatibility failed!".to_owned())))
            }
            
        }
        
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, serde::Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyOps {
  /// Compute digital signature or MAC.
  Sign,
  /// Verify digital signature or MAC.
  Verify,
  /// Encrypt content.
  Encrypt,
  /// Decrypt content and validate decryption, if applicable.
  Decrypt,
  /// Encrypt key.
  WrapKey,
  /// Decrypt key and validate decryption, if applicable.
  UnwrapKey,
  /// Derive key.
  DeriveKey,
  /// Derive bits not to be used as a key.
  DeriveBits,
}


#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PKUse {
    #[serde(rename = "sig")]
    Signature,
    #[serde(rename = "enc")]
    Encryption
}

