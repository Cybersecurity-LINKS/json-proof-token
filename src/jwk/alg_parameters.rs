use serde::{Deserialize, Serialize};

use crate::jpa::algs::ProofAlgorithm;

use super::{types::KeyType, curves::EllipticCurveTypes};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub enum Algorithm {
    Proof(ProofAlgorithm),

    // These are defined in the JWA rfc
    
    // Signature(SignatureAlgorithm), https://datatracker.ietf.org/doc/html/rfc7518#section-3
    // KeyManagement(KeyManagementAlgorithm), https://datatracker.ietf.org/doc/html/rfc7518#section-4
    // Encryption(EncryptionAlgorithm), https://datatracker.ietf.org/doc/html/rfc7518#section-5
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum JwkAlgorithmParameters {
    // TODO: to be done
    
    // EllipticCurve(JwkEllipticCurveKeyParameters),
    // RSA(JwkRSAKeyParameters),
    // OctetKey(JwkOctetKeyParameters),
    OctetKeyPair(JwkOctetKeyPairParameters),
}



#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct JwkOctetKeyPairParameters {
    pub kty: KeyType, 
    /// The "crv" (curve) parameter identifies the cryptographic curve used
    /// with the key.
    pub crv: EllipticCurveTypes,
    /// The "x" parameter contains the base64url encoded public key
    pub x: String,
    /// The "d" parameter contains the base64url encoded private key
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
}


impl JwkOctetKeyPairParameters {

    pub fn new(crv: EllipticCurveTypes, x: String, d: Option<String> ) -> Self{

        Self{
            kty: KeyType::OctetKeyPair,
            crv: crv,
            x: x,
            d: d
        }

    }

    /// Returns a clone without private key.
    pub fn to_public(&self) -> Self {
        Self {
            kty: KeyType::OctetKeyPair,
            crv: self.crv.clone(),
            x: self.x.clone(),
            d: None,
        }
    }

    /// Returns `true` if _all_ private key components of the key are unset, `false` otherwise.
    pub fn is_public(&self) -> bool {
        self.d.is_none()
    }

    /// Returns `true` if _all_ private key components of the key are set, `false` otherwise.
    pub fn is_private(&self) -> bool {
        self.d.is_some()
    }
}