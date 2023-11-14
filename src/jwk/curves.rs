use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum EllipticCurveTypes {
    #[serde(rename = "P-256")]
    P256,
    #[serde(rename = "P-384")]
    P384,
    #[serde(rename = "P-521")]
    P521,
    Ed25519,	
    Ed448,
    X25519,
    X448,
    #[serde(rename = "secp256k1")]
    Secp256K1,

    #[serde(rename = "Bls12381G2")]
    Bls12381G2

}


impl fmt::Display for EllipticCurveTypes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant_str = match self {
            EllipticCurveTypes::P256 => "P-256",
            EllipticCurveTypes::P384 => "P-384",
            EllipticCurveTypes::P521 => "P-521",
            EllipticCurveTypes::Ed25519 => "Ed25519",
            EllipticCurveTypes::Ed448 => "Ed448",
            EllipticCurveTypes::X25519 => "X25519",
            EllipticCurveTypes::X448 => "X448",
            EllipticCurveTypes::Secp256K1 => "secp256k1",
            EllipticCurveTypes::Bls12381G2 => "Bls12381G2",
        };
        write!(f, "{}", variant_str)
    }
}