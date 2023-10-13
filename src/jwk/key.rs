use std::error::Error;
use crate::{jwk::alg_parameters::JwkOctetKeyPairParameters, encoding::{base64url_encode, base64url_decode}, errors::CustomError};
use serde::{Deserialize, Serialize};
use zkryptium::{keys::{pair::KeyPair, bbsplus_key::BBSplusPublicKey}, schemes::algorithms::{BBS_BLS12381_SHA256, BBS_BLS12381_SHAKE256}};


use super::{alg_parameters::{JwkAlgorithmParameters, Algorithm}, utils::check_alg_curve_compatibility, types::KeyPairSubtype};



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

    pub fn generate(key_type: KeyPairSubtype) -> Result<Self, CustomError>{
        match key_type {
            KeyPairSubtype::BLS12381SHA256 => {
                let keypair = KeyPair::<BBS_BLS12381_SHA256>::generate(None, None);
                let pk = keypair.public_key().to_bytes();
                let sk = keypair.private_key().to_bytes();
                let okp_params = JwkOctetKeyPairParameters::new(super::curves::EllipticCurveTypes::Bls12_381, pk.to_vec(), Some(sk.to_vec()));
                let jwk_params = JwkAlgorithmParameters::OctetKeyPair(okp_params);
                Ok(Self{kid: None, pk_use: None, key_ops: None, alg: None, x5u: None, x5c: None, x5t: None, key_params: jwk_params })
            },
            KeyPairSubtype::BLS12381SHAKE256 => {
                let keypair = KeyPair::<BBS_BLS12381_SHAKE256>::generate(None, None);
                let pk = keypair.public_key().to_bytes();
                let sk = keypair.private_key().to_bytes();
                let okp_params = JwkOctetKeyPairParameters::new(super::curves::EllipticCurveTypes::Bls12_381, pk.to_vec(), Some(sk.to_vec()));
                let jwk_params = JwkAlgorithmParameters::OctetKeyPair(okp_params);
                Ok(Self{kid: None, pk_use: None, key_ops: None, alg: None, x5u: None, x5c: None, x5t: None, key_params: jwk_params })
            },
        }
    }

    pub fn set_kid(&mut self, kid: &str) {
        self.kid = Some(kid.to_string());
    }

    pub fn set_pk_use(&mut self, pk_use: PKUse) {
        self.pk_use = Some(pk_use);
    }

    pub fn set_key_ops(&mut self, key_ops: Vec<KeyOps>) {
        self.key_ops = Some(key_ops);
    }

    pub fn set_alg(&mut self, alg: Algorithm) {
        self.alg = Some(alg);
    }

    pub fn set_x5u(&mut self, x5u: &str) {
        self.x5u = Some(x5u.to_string());
    }

    pub fn set_x5c(&mut self, x5c: Vec<&str>) {
        self.x5c = Some(x5c.iter().map(|v| v.to_string()).collect());
    }

    pub fn set_x5t(&mut self, x5t: &str) {
        self.x5t = Some(x5t.to_string());
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


  //TODO: maybe add ProofGeneration and ProofVerification
}


#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PKUse {
    #[serde(rename = "sig")]
    Signature,
    #[serde(rename = "enc")]
    Encryption

    //TODO: maybe add Proof
}

