use std::str::FromStr;

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


impl FromStr for KeyPairSubtype {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_lowercase().as_str() {
            "bls12381sha256" => Ok(KeyPairSubtype::BLS12381SHA256),
            "bls12381shake256" => Ok(KeyPairSubtype::BLS12381SHAKE256),
            _ => Err(()),
        }
    }
}


