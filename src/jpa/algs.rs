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



use serde::{Deserialize, Serialize, Serializer, Deserializer};
use serde_json::Value;

use crate::{errors::CustomError, jpt::payloads::Payloads, jwk::{key::Jwk, alg_parameters::{JwkAlgorithmParameters, Algorithm}, utils::check_alg_curve_compatibility}, encoding::base64url_decode};

use super::{bbs::{BBSAlgorithm, ZkryptiumImplementation}, su::{SUAlgorithm, SUImplementation}, mac::{MACAlgorithm, MACImplementation}};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[allow(non_camel_case_types)]
pub enum ProofAlgorithm {

  ///TODO: we need two algorithms (BLS12381_SHA256 and BLS12381_SHAKE256) 
  /// We should also distinguish between the BBS algorithm standard and the one extended
  #[serde(rename = "BBS-BLS12381-SHA256")]
  BLS12381_SHA256,
  #[serde(rename = "BBS-BLS12381-SHAKE256")]
  BLS12381_SHAKE256,

  #[serde(rename = "BBS-BLS12381-SHA256-PROOF")]
  BLS12381_SHA256_PROOF,
  #[serde(rename = "BBS-BLS12381-SHAKE256-PROOF")]
  BLS12381_SHAKE256_PROOF,

  #[serde(rename = "SU-ES256")]
  SU_ES256,
  #[serde(rename = "MAC-H256")]
  MAC_H256,
  #[serde(rename = "MAC-H384")]
  MAC_H384,
  #[serde(rename = "MAC-H512")]
  MAC_H512,
  #[serde(rename = "MAC-K25519")]
  MAC_K25519,
  #[serde(rename = "MAC-K448")]
  MAC_K448,
  #[serde(rename = "MAC-H256K")]
  MAC_H256K
}


impl ProofAlgorithm{
  pub fn bbs_generate_issuer_proof<B: BBSAlgorithm>(&self, payloads: &Payloads, key: &Jwk, issuer_header: &[u8]) -> Result<Vec<u8>, CustomError> {
    let key_params = match &key.key_params {
            JwkAlgorithmParameters::OctetKeyPair(params) => {
                if params.is_private() == false {
                    return Err(CustomError::ProofGenerationError("key is not compatible".to_string()))
                }
                params
            },
            _ => return Err(CustomError::ProofGenerationError("key is not compatible".to_string()))
    };
        
    if check_alg_curve_compatibility(Algorithm::Proof(self.clone()), key_params.crv.clone()) == false {
      Err(CustomError::ProofGenerationError("key is not compatible".to_string()))
    } else {
      let pk = base64url_decode(&key_params.x);
      let sk = base64url_decode(&key_params.d.as_ref().unwrap());
      let messages: Vec<Vec<u8>> = payloads.0.iter().map(|p| serde_json::to_vec(&p.0).unwrap()).collect();
      let proof = match self {
        Self::BLS12381_SHA256 => B::sign_bls12381_sha256(&sk, &pk, issuer_header, messages).map_err(|_| CustomError::ProofGenerationError("Signature Failure!".to_string())),
        Self::BLS12381_SHAKE256 => B::sign_bls12381_shake256(&sk, &pk, issuer_header, messages).map_err(|_| CustomError::ProofGenerationError("Signature Failure!".to_string())),
        _ => unreachable!("This should NOT happen!")
      };
      
      proof
    }
  }

  pub fn bbs_verify_issuer_proof<B: BBSAlgorithm>(&self, key: &Jwk, proof: &[u8], issuer_header: &[u8], payloads: &Payloads) -> Result<(), CustomError> {
    let key_params = match &key.key_params {
      JwkAlgorithmParameters::OctetKeyPair(params) => {
          if params.is_public() == false {
              return Err(CustomError::ProofVerificationError("key is not compatible".to_string()))
          }
          params
      },
      _ => return Err(CustomError::ProofVerificationError("key is not compatible".to_string()))
    };
  
    if check_alg_curve_compatibility(Algorithm::Proof(self.clone()), key_params.crv.clone()) == false {
        Err(CustomError::ProofGenerationError("key is not compatible".to_string()))
    } else {
        let pk = base64url_decode(&key_params.x);
        let messages: Vec<Vec<u8>> = payloads.0.iter().map(|p| serde_json::to_vec(&p.0).unwrap()).collect();  
        let check = match self {
            Self::BLS12381_SHA256 => {
              B::verify_bls12381_sha256(&pk, proof, issuer_header, messages).map_err(|_| CustomError::ProofVerificationError("Signature verification Failure!".to_string()))
            },
            Self::BLS12381_SHAKE256 => {
              B::verify_bls12381_shake256(&pk, proof, issuer_header, messages).map_err(|_| CustomError::ProofVerificationError("Signature verification Failure!".to_string()))
            },
            _ => unreachable!()
        };

        check
    }
  }

  pub fn bbs_generate_presentation_proof<B: BBSAlgorithm>(&self, signature: &[u8], payloads: &Payloads, key: &Jwk, issuer_header: &[u8], presentation_header: &[u8]) -> Result<Vec<u8>, CustomError> {
    let key_params = match &key.key_params {
        JwkAlgorithmParameters::OctetKeyPair(params) => {
            if params.is_public() == false {
                return Err(CustomError::ProofGenerationError("key is not compatible".to_string()))
            }
            params
        },
        _ => return Err(CustomError::ProofGenerationError("key is not compatible".to_string()))
    };
    
    if check_alg_curve_compatibility(Algorithm::Proof(self.clone()), key_params.crv.clone()) == false {
        Err(CustomError::ProofGenerationError("key is not compatible".to_string()))
    } else {
        let pk = base64url_decode(&key_params.x);
        let revealed_message_indexes = payloads.get_disclosed_indexes();
        let messages: Vec<Vec<u8>> = payloads.0.iter().map(|p| serde_json::to_vec(&p.0).unwrap()).collect();  

        let proof = match self {
            Self::BLS12381_SHA256_PROOF => {
              B::proofgen_bls12381_sha256(&pk, signature, issuer_header, presentation_header, messages, &revealed_message_indexes).map_err(|_| CustomError::ProofGenerationError("Proof generation Failure!".to_string()))
            },
            Self::BLS12381_SHAKE256_PROOF => {
              B::proofgen_bls12381_shake256(&pk, signature, issuer_header, presentation_header, messages, &revealed_message_indexes).map_err(|_| CustomError::ProofGenerationError("Proof generation Failure!".to_string()))
            },
            _ => unreachable!()
        };

        proof
    }
  }
  
  pub fn bbs_verify_presentation_proof<B: BBSAlgorithm>(&self, key: &Jwk, proof: &[u8], presentation_header: &[u8], issuer_header: &[u8], payloads: &Payloads) -> Result<(), CustomError> {
    let key_params = match &key.key_params {
        JwkAlgorithmParameters::OctetKeyPair(params) => {
            if params.is_public() == false {
                return Err(CustomError::ProofVerificationError("key is not compatible".to_string()))
            }
            params
        },
        _ => return Err(CustomError::ProofVerificationError("key is not compatible".to_string()))
    };
    
    if check_alg_curve_compatibility(Algorithm::Proof(self.clone()), key_params.crv.clone()) == false {
        Err(CustomError::ProofGenerationError("key is not compatible".to_string()))
    } else {
        let pk = base64url_decode(&key_params.x);
        let disclosed_indexes = payloads.get_disclosed_indexes();
        let disclosed_messages: Vec<Vec<u8>> = payloads.get_disclosed_payloads().iter().map(|p| serde_json::to_vec(&p).unwrap()).collect();  

        let check = match self {
            Self::BLS12381_SHA256_PROOF => {
              B::proofverify_bls12381_sha256(&pk, proof, issuer_header, presentation_header, disclosed_messages, &disclosed_indexes).map_err(|_| CustomError::ProofVerificationError("Proof verification Failure!".to_string()))
            },
            Self::BLS12381_SHAKE256_PROOF => {
              B::proofverify_bls12381_sha256(&pk, proof, issuer_header, presentation_header, disclosed_messages, &disclosed_indexes).map_err(|_| CustomError::ProofVerificationError("Proof verification Failure!".to_string()))
            },
            _ => unreachable!()
        };

        check
    }
  }
}

