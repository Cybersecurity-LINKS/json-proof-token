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

use crate::{encoding::base64url_encode, jpa::algs::ProofAlgorithm};
use serde::{Deserialize, Serialize};
use std::fmt;

use super::{curves::EllipticCurveTypes, types::KeyType};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(untagged)]
pub enum Algorithm {
    Proof(ProofAlgorithm),
    // These are defined in the JWA rfc

    // Signature(SignatureAlgorithm), https://datatracker.ietf.org/doc/html/rfc7518#section-3
    // KeyManagement(KeyManagementAlgorithm), https://datatracker.ietf.org/doc/html/rfc7518#section-4
    // Encryption(EncryptionAlgorithm), https://datatracker.ietf.org/doc/html/rfc7518#section-5
}

impl fmt::Display for Algorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Algorithm::Proof(proof_algorithm) => write!(f, "{}", proof_algorithm),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(untagged)]
pub enum JwkAlgorithmParameters {
    EllipticCurve(JwkEllipticCurveKeyParameters),
    OctetKeyPair(JwkOctetKeyPairParameters),
}

impl JwkAlgorithmParameters {
    pub fn to_public(&self) -> Option<Self> {
        match self {
            Self::OctetKeyPair(inner) => Some(Self::OctetKeyPair(inner.to_public())),
            Self::EllipticCurve(value) => Some(Self::EllipticCurve(value.to_public())),
        }
    }

    pub fn is_public(&self) -> bool {
        match self {
            Self::OctetKeyPair(value) => value.is_public(),
            Self::EllipticCurve(value) => value.is_public(),
        }
    }

    pub fn is_private(&self) -> bool {
        match self {
            Self::OctetKeyPair(value) => value.is_private(),
            Self::EllipticCurve(value) => value.is_private(),
        }
    }
}

/// Octect Key Pair representation of BLS keys
///
/// For now using this representation https://www.rfc-editor.org/rfc/rfc8037
///
/// Maybe in future change to [this](https://datatracker.ietf.org/doc/html/draft-ietf-cose-bls-key-representations-03)
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct JwkOctetKeyPairParameters {
    pub kty: KeyType,
    /// The "crv" (curve) parameter identifies the cryptographic curve used
    /// with the key.
    ///
    /// [More Info](https://datatracker.ietf.org/doc/html/draft-ietf-cose-bls-key-representations-03#curve-parameter-registration)
    pub crv: EllipticCurveTypes,
    /// Represents the base64url encoded public key
    ///
    /// [More Info](https://datatracker.ietf.org/doc/html/draft-ietf-cose-bls-key-representations-03#section-2.2.1)
    pub x: String, // Public Key
    /// The "d" parameter contains the base64url encoded private key
    ///
    /// [More Info](https://datatracker.ietf.org/doc/html/draft-ietf-cose-bls-key-representations-03#section-2.2.1)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
}

impl JwkOctetKeyPairParameters {
    pub fn new<T: AsRef<[u8]>>(crv: EllipticCurveTypes, x: T, d: Option<T>) -> Self {
        Self {
            kty: KeyType::OctetKeyPair,
            crv: crv,
            x: base64url_encode(x),
            d: match d {
                Some(d) => Some(base64url_encode(d)),
                None => None,
            },
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

/// EC representation of BLS keys
///
/// Barreto-Lynn-Scott Elliptic Curve Key Representations for JOSE and COSE
/// [More Info](https://datatracker.ietf.org/doc/html/draft-ietf-cose-bls-key-representations-05)
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct JwkEllipticCurveKeyParameters {
    pub kty: KeyType,
    /// The "crv" (curve) parameter identifies the cryptographic curve used
    /// with the key.
    ///
    /// [More Info](https://datatracker.ietf.org/doc/html/draft-ietf-cose-bls-key-representations-05#curve-parameter-registration)
    pub crv: EllipticCurveTypes,
    /// Represents the base64url encoded x coordinate of the curve point for the public key
    ///
    /// [More Info](https://datatracker.ietf.org/doc/html/draft-ietf-cose-bls-key-representations-05#name-json-web-key-representation)
    pub x: String, // Public Key's x-coordinate
    /// Represents the base64url encoded y coordinate of the curve point for the public key
    ///
    /// [More Info](https://datatracker.ietf.org/doc/html/draft-ietf-cose-bls-key-representations-05#name-json-web-key-representation)
    pub y: String, // Public Key's y-coordinate
    /// The "d" parameter contains the base64url encoded private key
    ///
    /// [More Info](https://datatracker.ietf.org/doc/html/draft-ietf-cose-bls-key-representations-05#name-json-web-key-representation)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<String>,
}

impl JwkEllipticCurveKeyParameters {
    pub fn new(crv: EllipticCurveTypes, x: &[u8], y: &[u8], d: Option<&[u8]>) -> Self {
        Self {
            kty: KeyType::EllipticCurve,
            crv: crv,
            x: base64url_encode(x),
            y: base64url_encode(y),
            d: match d {
                Some(d) => Some(base64url_encode(d)),
                None => None,
            },
        }
    }

    /// Returns a clone without private key.
    pub fn to_public(&self) -> Self {
        Self {
            kty: KeyType::OctetKeyPair,
            crv: self.crv.clone(),
            x: self.x.clone(),
            y: self.y.clone(),
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
