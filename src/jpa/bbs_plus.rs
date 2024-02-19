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

use serde::{Deserialize, Serialize};
use zkryptium::{
    bbsplus::{
        keys::{BBSplusPublicKey, BBSplusSecretKey},
        proof::BBSplusPoKSignature,
        signature::BBSplusSignature,
    },
    schemes::{
        algorithms::{BBS_BLS12381_SHA256, BBS_BLS12381_SHAKE256},
        generics::{PoKSignature, Signature},
    },
    utils::message::BBSplusMessage,
};

use crate::{
    encoding::base64url_decode,
    errors::CustomError,
    jpt::payloads::Payloads,
    jwk::{
        alg_parameters::{Algorithm, JwkAlgorithmParameters},
        key::Jwk,
        utils::{check_alg_curve_compatibility, check_presentation_alg_curve_compatibility},
    },
};

use super::algs::{PresentationProofAlgorithm, ProofAlgorithm};

#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct BBSplusAlgorithm {}

impl BBSplusAlgorithm {
    pub fn generate_issuer_proof(
        alg: ProofAlgorithm,
        payloads: &Payloads,
        key: &Jwk,
        issuer_header: &[u8],
    ) -> Result<Vec<u8>, CustomError> {
        let key_params = match &key.key_params {
            JwkAlgorithmParameters::OctetKeyPair(params) => {
                if params.is_private() == false {
                    return Err(CustomError::ProofGenerationError(
                        "key is not compatible".to_string(),
                    ));
                }
                params
            } // _ => {
              //     return Err(CustomError::ProofGenerationError(
              //         "key is not compatible".to_string(),
              //     ))
              // }
        };

        if check_alg_curve_compatibility(Algorithm::Proof(alg.clone()), key_params.crv.clone())
            == false
        {
            Err(CustomError::ProofGenerationError(
                "key is not compatible".to_string(),
            ))
        } else {
            let dec_pk: [u8; 96] = base64url_decode(&key_params.x).try_into().map_err(|_| {
                CustomError::ProofGenerationError("key is not compatible".to_string())
            })?;

            let pk = BBSplusPublicKey::from_bytes(&dec_pk);
            let sk =
                BBSplusSecretKey::from_bytes(&base64url_decode(key_params.d.as_ref().unwrap()));

            let proof = match alg {
                ProofAlgorithm::BLS12381_SHA256 => {
                    let messages: Vec<BBSplusMessage> = payloads
                        .0
                        .iter()
                        .map(|p| {
                            BBSplusMessage::map_message_to_scalar_as_hash::<BBS_BLS12381_SHA256>(
                                &serde_json::to_vec(&p.0).unwrap(),
                                None,
                            )
                        })
                        .collect();
                    Signature::<BBS_BLS12381_SHA256>::sign(
                        Some(&messages),
                        &sk,
                        &pk,
                        None,
                        Some(issuer_header),
                    )
                    .to_bytes()
                }
                ProofAlgorithm::BLS12381_SHAKE256 => {
                    let messages: Vec<BBSplusMessage> = payloads
                        .0
                        .iter()
                        .map(|p| {
                            BBSplusMessage::map_message_to_scalar_as_hash::<BBS_BLS12381_SHAKE256>(
                                &serde_json::to_vec(&p.0).unwrap(),
                                None,
                            )
                        })
                        .collect();
                    Signature::<BBS_BLS12381_SHAKE256>::sign(
                        Some(&messages),
                        &sk,
                        &pk,
                        None,
                        Some(issuer_header),
                    )
                    .to_bytes()
                }
                _ => unreachable!(),
            };

            Ok(proof.to_vec())
        }
    }

    pub fn verify_issuer_proof(
        alg: ProofAlgorithm,
        key: &Jwk,
        proof: &[u8],
        issuer_header: &[u8],
        payloads: &Payloads,
    ) -> Result<(), CustomError> {
        let key_params = match &key.key_params {
            JwkAlgorithmParameters::OctetKeyPair(params) => {
                if params.is_public() == false {
                    return Err(CustomError::ProofGenerationError(
                        "key is not compatible".to_string(),
                    ));
                }
                params
            } // _ => {
              //     return Err(CustomError::ProofGenerationError(
              //         "key is not compatible".to_string(),
              //     ))
              // }
        };

        if check_alg_curve_compatibility(Algorithm::Proof(alg.clone()), key_params.crv.clone())
            == false
        {
            Err(CustomError::ProofGenerationError(
                "key is not compatible".to_string(),
            ))
        } else {
            let dec_pk: [u8; 96] = base64url_decode(&key_params.x).try_into().map_err(|_| {
                CustomError::ProofGenerationError("key is not compatible".to_string())
            })?;
            let pk = BBSplusPublicKey::from_bytes(&dec_pk);
            let proof = BBSplusSignature::from_bytes(proof.try_into().unwrap()).unwrap();
            let check = match alg {
                ProofAlgorithm::BLS12381_SHA256 => {
                    let messages: Vec<BBSplusMessage> = payloads
                        .0
                        .iter()
                        .map(|p| {
                            BBSplusMessage::map_message_to_scalar_as_hash::<BBS_BLS12381_SHA256>(
                                &serde_json::to_vec(&p.0).unwrap(),
                                None,
                            )
                        })
                        .collect();
                    let proof = Signature::<BBS_BLS12381_SHA256>::BBSplus(proof);
                    proof.verify(&pk, Some(&messages), None, Some(issuer_header))
                }
                ProofAlgorithm::BLS12381_SHAKE256 => {
                    let messages: Vec<BBSplusMessage> = payloads
                        .0
                        .iter()
                        .map(|p| {
                            BBSplusMessage::map_message_to_scalar_as_hash::<BBS_BLS12381_SHAKE256>(
                                &serde_json::to_vec(&p.0).unwrap(),
                                None,
                            )
                        })
                        .collect();

                    let proof = Signature::<BBS_BLS12381_SHAKE256>::BBSplus(proof);
                    proof.verify(&pk, Some(&messages), None, Some(issuer_header))
                }
                _ => unreachable!(),
            };

            match check {
                true => Ok(()),
                false => Err(CustomError::InvalidIssuedProof),
            }
        }
    }

    pub fn generate_presentation_proof(
        alg: PresentationProofAlgorithm,
        signature: &[u8],
        payloads: &Payloads,
        key: &Jwk,
        issuer_header: &[u8],
        presentation_header: &[u8],
    ) -> Result<Vec<u8>, CustomError> {
        let key_params = match &key.key_params {
            JwkAlgorithmParameters::OctetKeyPair(params) => {
                if params.is_public() == false {
                    return Err(CustomError::ProofGenerationError(
                        "key is not compatible".to_string(),
                    ));
                }
                params
            } // _ => {
              //     return Err(CustomError::ProofGenerationError(
              //         "key is not compatible".to_string(),
              //     ))
              // }
        };

        if check_presentation_alg_curve_compatibility(alg, key_params.crv.clone()) == false {
            Err(CustomError::ProofGenerationError(
                "key is not compatible".to_string(),
            ))
        } else {
            let dec_pk: [u8; 96] = base64url_decode(&key_params.x).try_into().map_err(|_| {
                CustomError::ProofGenerationError("key is not compatible".to_string())
            })?;
            let pk = BBSplusPublicKey::from_bytes(&dec_pk);
            let revealed_message_indexes = payloads.get_disclosed_indexes();
            let signature = BBSplusSignature::from_bytes(signature.try_into().unwrap()).unwrap();

            let proof = match alg {
                PresentationProofAlgorithm::BLS12381_SHA256_PROOF => {
                    let messages: Vec<BBSplusMessage> = payloads
                        .0
                        .iter()
                        .map(|p| {
                            BBSplusMessage::map_message_to_scalar_as_hash::<BBS_BLS12381_SHA256>(
                                &serde_json::to_vec(&p.0).unwrap(),
                                None,
                            )
                        })
                        .collect();
                    PoKSignature::<BBS_BLS12381_SHA256>::proof_gen(
                        &signature,
                        &pk,
                        Some(&messages),
                        None,
                        Some(&revealed_message_indexes),
                        Some(issuer_header),
                        Some(presentation_header),
                        None,
                    )
                    .to_bytes()
                }
                PresentationProofAlgorithm::BLS12381_SHAKE256_PROOF => {
                    let messages: Vec<BBSplusMessage> = payloads
                        .0
                        .iter()
                        .map(|p| {
                            BBSplusMessage::map_message_to_scalar_as_hash::<BBS_BLS12381_SHAKE256>(
                                &serde_json::to_vec(&p.0).unwrap(),
                                None,
                            )
                        })
                        .collect();
                    PoKSignature::<BBS_BLS12381_SHAKE256>::proof_gen(
                        &signature,
                        &pk,
                        Some(&messages),
                        None,
                        Some(&revealed_message_indexes),
                        Some(issuer_header),
                        Some(presentation_header),
                        None,
                    )
                    .to_bytes()
                }
                _ => unreachable!(),
            };

            Ok(proof.to_vec())
        }
    }

    pub fn verify_presentation_proof(
        alg: PresentationProofAlgorithm,
        key: &Jwk,
        proof: &[u8],
        presentation_header: &[u8],
        issuer_header: &[u8],
        payloads: &Payloads,
    ) -> Result<(), CustomError> {
        let key_params = match &key.key_params {
            JwkAlgorithmParameters::OctetKeyPair(params) => {
                if params.is_public() == false {
                    return Err(CustomError::ProofGenerationError(
                        "key is not compatible".to_string(),
                    ));
                }
                params
            } // _ => {
              //     return Err(CustomError::ProofGenerationError(
              //         "key is not compatible".to_string(),
              //     ))
              // }
        };

        if check_presentation_alg_curve_compatibility(alg, key_params.crv.clone()) == false {
            Err(CustomError::ProofGenerationError(
                "key is not compatible".to_string(),
            ))
        } else {
            let dec_pk: [u8; 96] = base64url_decode(&key_params.x).try_into().map_err(|_| {
                CustomError::ProofGenerationError("key is not compatible".to_string())
            })?;
            let pk = BBSplusPublicKey::from_bytes(&dec_pk);
            let disclosed_indexes = payloads.get_disclosed_indexes();
            let proof = BBSplusPoKSignature::from_bytes(proof.try_into().unwrap());
            let check = match alg {
                PresentationProofAlgorithm::BLS12381_SHA256_PROOF => {
                    let messages: Vec<BBSplusMessage> = payloads
                        .get_disclosed_payloads()
                        .iter()
                        .map(|p| {
                            BBSplusMessage::map_message_to_scalar_as_hash::<BBS_BLS12381_SHA256>(
                                &serde_json::to_vec(p).unwrap(),
                                None,
                            )
                        })
                        .collect();
                    let proof = PoKSignature::<BBS_BLS12381_SHA256>::BBSplus(proof);
                    proof.proof_verify(
                        &pk,
                        Some(&messages),
                        None,
                        Some(&disclosed_indexes),
                        Some(issuer_header),
                        Some(presentation_header),
                    )
                }
                PresentationProofAlgorithm::BLS12381_SHAKE256_PROOF => {
                    let messages: Vec<BBSplusMessage> = payloads
                        .get_disclosed_payloads()
                        .iter()
                        .map(|p| {
                            BBSplusMessage::map_message_to_scalar_as_hash::<BBS_BLS12381_SHAKE256>(
                                &serde_json::to_vec(p).unwrap(),
                                None,
                            )
                        })
                        .collect();

                    let proof = PoKSignature::<BBS_BLS12381_SHAKE256>::BBSplus(proof);
                    proof.proof_verify(
                        &pk,
                        Some(&messages),
                        None,
                        Some(&disclosed_indexes),
                        Some(issuer_header),
                        Some(presentation_header),
                    )
                }
                _ => unreachable!(),
            };

            match check {
                true => Ok(()),
                false => Err(CustomError::InvalidPresentedProof),
            }
        }
    }
}
