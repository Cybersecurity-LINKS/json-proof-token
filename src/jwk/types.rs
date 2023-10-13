use serde::{Serialize, Deserialize};


#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Copy, Clone)]
pub enum KeyType {
    #[serde(rename = "EC")]
    EllipticCurve,
    #[serde(rename = "RSA")]
    RSA,
    #[serde(rename = "oct")]
    Octet,
    #[serde(rename = "OKP")]
    OctetKeyPair,
}

#[derive(Debug, Eq, PartialEq, Serialize, Deserialize, Copy, Clone)]
pub enum KeyPairSubtype {
    BLS12381SHA256,
    BLS12381SHAKE256
}

