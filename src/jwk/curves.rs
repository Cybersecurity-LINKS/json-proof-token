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
