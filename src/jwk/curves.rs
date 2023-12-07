// Copyright 2023 Fondazione LINKS

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.




use std::{fmt, str::FromStr};
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

impl FromStr for EllipticCurveTypes {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "P-256" => Ok(EllipticCurveTypes::P256),
            "P-384" => Ok(EllipticCurveTypes::P384),
            "P-521" => Ok(EllipticCurveTypes::P521),
            "Ed25519" => Ok(EllipticCurveTypes::Ed25519),
            "Ed448" => Ok(EllipticCurveTypes::Ed448),
            "X25519" => Ok(EllipticCurveTypes::X25519),
            "X448" => Ok(EllipticCurveTypes::X448),
            "secp256k1" => Ok(EllipticCurveTypes::Secp256K1),
            "Bls12381G2" => Ok(EllipticCurveTypes::Bls12381G2),
            _ => Err(()),
        }
    }
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