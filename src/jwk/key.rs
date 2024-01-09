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



use crate::{jwk::alg_parameters::JwkOctetKeyPairParameters, errors::CustomError};
use serde::{Deserialize, Serialize};
use zkryptium::{schemes::algorithms::{BBS_BLS12381_SHA256, BBS_BLS12381_SHAKE256}, keys::pair::KeyPair};


use super::{alg_parameters::{JwkAlgorithmParameters, Algorithm}, types::KeyPairSubtype};



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
                let okp_params = JwkOctetKeyPairParameters::new(super::curves::EllipticCurveTypes::Bls12381G2, pk.as_ref(), Some(sk.as_ref()));
                let jwk_params = JwkAlgorithmParameters::OctetKeyPair(okp_params);
                Ok(Self{kid: None, pk_use: None, key_ops: None, alg: None, x5u: None, x5c: None, x5t: None, key_params: jwk_params })
            },
            KeyPairSubtype::BLS12381SHAKE256 => {
                let keypair = KeyPair::<BBS_BLS12381_SHAKE256>::generate(None, None);
                let pk = keypair.public_key().to_bytes();
                let sk = keypair.private_key().to_bytes();
                let okp_params = JwkOctetKeyPairParameters::new(super::curves::EllipticCurveTypes::Bls12381G2, pk.as_ref(), Some(sk.as_ref()));
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

    /// Returns `true` if _all_ private key components of the key are unset, `false` otherwise.
    pub fn is_public(&self) -> bool {
        self.key_params.is_public()
    }

    /// Returns `true` if _all_ private key components of the key are set, `false` otherwise.
    pub fn is_private(&self) -> bool {
        self.key_params.is_private()
    }

    pub fn from_key_params(key_params: JwkAlgorithmParameters) -> Self {
        let params: JwkAlgorithmParameters = key_params.into();
        Self{
            kid: None,
            pk_use: None,
            key_ops: None,
            alg: None,
            x5u: None,
            x5c: None,
            x5t: None,
            key_params: params,
        }
    }

    pub fn to_public(&self) -> Option<Jwk> {
        let mut public: Jwk = Jwk::from_key_params(self.key_params.to_public()?);
    
        if let Some(value) = &self.kid {
            public.set_kid(value);
        }

        if let Some(value) = self.pk_use {
            public.set_pk_use(value);
        }
    
        if let Some(value) = &self.key_ops {
            public.set_key_ops(value.iter().map(|op| op.inverse()).collect());
        }
    
        if let Some(value) = self.alg {
            public.set_alg(value);
        }

        if let Some(value) = &self.x5u {
            public.set_x5u(value);
        }

        if let Some(value) = &self.x5c {
            public.set_x5c(value.iter().map(|x| x.as_str()).collect());
        }

        if let Some(value) = &self.x5t {
            public.set_x5t(value);
        }
    
        Some(public)
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

  /// Generate a proof
  ProofGeneration,
  ///Verify a proof
  ProofVerification
}


impl KeyOps {
    pub const fn inverse(&self) -> Self {
        match self {
            Self::Sign => Self::Verify,
            Self::Verify => Self::Sign,
            Self::Encrypt => Self::Decrypt,
            Self::Decrypt => Self::Encrypt,
            Self::WrapKey => Self::UnwrapKey,
            Self::UnwrapKey => Self::WrapKey,
            Self::DeriveKey => Self::DeriveKey,
            Self::DeriveBits => Self::DeriveBits,
            Self::ProofGeneration => Self::ProofVerification,
            Self::ProofVerification => Self::ProofVerification,
        }
      }
}


#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum PKUse {
    #[serde(rename = "sig")]
    Signature,
    #[serde(rename = "enc")]
    Encryption,
    #[serde(rename = "proof")]
    Proof
}

