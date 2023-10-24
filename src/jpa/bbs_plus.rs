use serde::{Deserialize, Serialize};
use zkryptium::{bbsplus::{keys::{BBSplusPublicKey, BBSplusSecretKey}, signature::BBSplusSignature, proof::BBSplusPoKSignature}, utils::message::BBSplusMessage, schemes::{generics::{Signature, PoKSignature}, algorithms::{BBS_BLS12381_SHA256, BBS_BLS12381_SHAKE256, Scheme}}};

use crate::{jwk::{key::Jwk, utils::{check_alg_curve_compatibility}, alg_parameters::{Algorithm, JwkAlgorithmParameters}}, jwp::header::IssuerProtectedHeader, errors::CustomError, encoding::base64url_decode, jpt::payloads::Payloads};

use super::algs::ProofAlgorithm;


#[derive(Clone, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct BBSplusAlgorithm{}

impl BBSplusAlgorithm {
    pub fn generate_issuer_proof(alg: ProofAlgorithm, payloads: &Payloads, key: &Jwk, issuer_header: &str) -> Result<Vec<u8>, CustomError> {
        let key_params = match &key.key_params {
            JwkAlgorithmParameters::OctetKeyPair(params) => {
                if params.is_private() == false {
                    return Err(CustomError::ProofGenerationError("key is not compatible".to_string()))
                }
                params
            },
            _ => return Err(CustomError::ProofGenerationError("key is not compatible".to_string()))
        };
        
        if check_alg_curve_compatibility(Algorithm::Proof(alg.clone()), key_params.crv.clone()) == false {
            Err(CustomError::ProofGenerationError("key is not compatible".to_string()))
        } else {
            let dec_pk = base64url_decode(&key_params.x);
            let pk = BBSplusPublicKey::from_bytes(&dec_pk);
            let sk = BBSplusSecretKey::from_bytes(&base64url_decode(key_params.d.as_ref().unwrap()));
            
            let proof = match alg {
                ProofAlgorithm::BLS12381_SHA256 => {
                    let messages: Vec<BBSplusMessage> = payloads.0
                    .iter()
                    .map(|p| BBSplusMessage::map_message_to_scalar_as_hash::<<BBS_BLS12381_SHA256 as Scheme>::Ciphersuite>(p.0.as_bytes(), None))
                    .collect();
                    Signature::<BBS_BLS12381_SHA256>::sign(Some(&messages), &sk, &pk, None, Some(issuer_header.as_bytes())).to_bytes()
            
                },
                ProofAlgorithm::BLS12381_SHAKE256 => {
                    let messages: Vec<BBSplusMessage> = payloads.0
                    .iter()
                    .map(|p| BBSplusMessage::map_message_to_scalar_as_hash::<<BBS_BLS12381_SHAKE256 as Scheme>::Ciphersuite>(p.0.as_bytes(), None))
                    .collect();
                    Signature::<BBS_BLS12381_SHAKE256>::sign(Some(&messages), &sk, &pk, None, Some(issuer_header.as_bytes())).to_bytes()
                },
                _ => unreachable!()
            };

            Ok(proof.to_vec())
        }
    }

    pub fn verify_issuer_proof(alg: ProofAlgorithm, key: &Jwk, proof: &str, issuer_header: &str, payloads: &Payloads) -> Result<(), CustomError> {
        let key_params = match &key.key_params {
            JwkAlgorithmParameters::OctetKeyPair(params) => {
                if params.is_public() == false {
                    return Err(CustomError::ProofGenerationError("key is not compatible".to_string()))
                }
                params
            },
            _ => return Err(CustomError::ProofGenerationError("key is not compatible".to_string()))
        };
        
        if check_alg_curve_compatibility(Algorithm::Proof(alg.clone()), key_params.crv.clone()) == false {
            Err(CustomError::ProofGenerationError("key is not compatible".to_string()))
        } else {
            let dec_pk = base64url_decode(&key_params.x);
            let pk = BBSplusPublicKey::from_bytes(&dec_pk);
        
            let proof = BBSplusSignature::from_bytes(base64url_decode(proof).as_slice().try_into().unwrap()).unwrap();
            let check = match alg {
                ProofAlgorithm::BLS12381_SHA256 => {
                    let messages: Vec<BBSplusMessage> = payloads.0
                    .iter()
                    .map(|p| BBSplusMessage::map_message_to_scalar_as_hash::<<BBS_BLS12381_SHA256 as Scheme>::Ciphersuite>(p.0.as_bytes(), None))
                    .collect();
                    let proof = Signature::<BBS_BLS12381_SHA256>::BBSplus(proof);
                    proof.verify(&pk, Some(&messages), None, Some(issuer_header.as_bytes()))
                    
                },
                ProofAlgorithm::BLS12381_SHAKE256 => {
                    let messages: Vec<BBSplusMessage> = payloads.0
                    .iter()
                    .map(|p| BBSplusMessage::map_message_to_scalar_as_hash::<<BBS_BLS12381_SHAKE256 as Scheme>::Ciphersuite>(p.0.as_bytes(), None))
                    .collect();

                    let proof = Signature::<BBS_BLS12381_SHAKE256>::BBSplus(proof);
                    proof.verify(&pk, Some(&messages), None, Some(issuer_header.as_bytes()))  
                },
                _ => unreachable!()
            };

            match check {
                true => Ok(()),
                false => Err(CustomError::InvalidIssuedProof)
                
            }
        }
    }

    pub fn generate_presentation_proof(alg: ProofAlgorithm, signature: &[u8], payloads: &Payloads, key: &Jwk, issuer_header: &str, presentation_header: &str) ->  Result<Vec<u8>, CustomError> {
        let key_params = match &key.key_params {
            JwkAlgorithmParameters::OctetKeyPair(params) => {
                if params.is_public() == false {
                    return Err(CustomError::ProofGenerationError("key is not compatible".to_string()))
                }
                params
            },
            _ => return Err(CustomError::ProofGenerationError("key is not compatible".to_string()))
        };
        
        if check_alg_curve_compatibility(Algorithm::Proof(alg.clone()), key_params.crv.clone()) == false {
            Err(CustomError::ProofGenerationError("key is not compatible".to_string()))
        } else {
            let dec_pk = base64url_decode(&key_params.x);
            let pk = BBSplusPublicKey::from_bytes(&dec_pk);
            let revealed_message_indexes = payloads.get_disclosed_indexes();
            let signature = BBSplusSignature::from_bytes(signature.try_into().unwrap()).unwrap();

            let proof = match alg {
                ProofAlgorithm::BLS12381_SHA256_PROOF => {
                    let messages: Vec<BBSplusMessage> = payloads.0
                    .iter()
                    .map(|p| BBSplusMessage::map_message_to_scalar_as_hash::<<BBS_BLS12381_SHA256 as Scheme>::Ciphersuite>(p.0.as_bytes(), None))
                    .collect();
                    PoKSignature::<BBS_BLS12381_SHA256>::proof_gen(&signature, &pk, Some(&messages), None, Some(&revealed_message_indexes), Some(issuer_header.as_bytes()), Some(presentation_header.as_bytes()), None).to_bytes()
            
                },
                ProofAlgorithm::BLS12381_SHAKE256_PROOF => {
                    let messages: Vec<BBSplusMessage> = payloads.0
                    .iter()
                    .map(|p| BBSplusMessage::map_message_to_scalar_as_hash::<<BBS_BLS12381_SHAKE256 as Scheme>::Ciphersuite>(p.0.as_bytes(), None))
                    .collect();
                    PoKSignature::<BBS_BLS12381_SHAKE256>::proof_gen(&signature, &pk, Some(&messages), None, Some(&revealed_message_indexes), Some(issuer_header.as_bytes()), Some(presentation_header.as_bytes()), None).to_bytes()
                },
                _ => unreachable!()
            };

            Ok(proof.to_vec())
        }
    }

    pub fn verify_presentation_proof(alg: ProofAlgorithm, key: &Jwk, proof: &str, presentation_header: &str, issuer_header: &str, payloads: &Payloads) -> Result<(), CustomError>  {
        let key_params = match &key.key_params {
            JwkAlgorithmParameters::OctetKeyPair(params) => {
                if params.is_public() == false {
                    return Err(CustomError::ProofGenerationError("key is not compatible".to_string()))
                }
                params
            },
            _ => return Err(CustomError::ProofGenerationError("key is not compatible".to_string()))
        };
        
        if check_alg_curve_compatibility(Algorithm::Proof(alg.clone()), key_params.crv.clone()) == false {
            Err(CustomError::ProofGenerationError("key is not compatible".to_string()))
        } else {
            let dec_pk = base64url_decode(&key_params.x);
            let pk = BBSplusPublicKey::from_bytes(&dec_pk);
            let disclosed_indexes = payloads.get_disclosed_indexes();
            let proof = BBSplusPoKSignature::from_bytes(base64url_decode(proof).as_slice().try_into().unwrap());
            let check = match alg {
                ProofAlgorithm::BLS12381_SHA256_PROOF => {
                    let messages: Vec<BBSplusMessage> = payloads.get_disclosed_payloads()
                    .iter()
                    .map(|p| BBSplusMessage::map_message_to_scalar_as_hash::<<BBS_BLS12381_SHA256 as Scheme>::Ciphersuite>(p.as_bytes(), None))
                    .collect();
                    let proof = PoKSignature::<BBS_BLS12381_SHA256>::BBSplus(proof);
                    proof.proof_verify(&pk, Some(&messages), None, Some(&disclosed_indexes), Some(issuer_header.as_bytes()), Some(presentation_header.as_bytes()))
                    
                },
                ProofAlgorithm::BLS12381_SHAKE256_PROOF => {
                    let messages: Vec<BBSplusMessage> = payloads.get_disclosed_payloads()
                    .iter()
                    .map(|p| BBSplusMessage::map_message_to_scalar_as_hash::<<BBS_BLS12381_SHAKE256 as Scheme>::Ciphersuite>(p.as_bytes(), None))
                    .collect();

                    let proof = PoKSignature::<BBS_BLS12381_SHAKE256>::BBSplus(proof);
                    proof.proof_verify(&pk, Some(&messages), None, Some(&disclosed_indexes), Some(issuer_header.as_bytes()), Some(presentation_header.as_bytes()))
                    
                },
                _ => unreachable!()
            };

            match check {
                true => Ok(()),
                false => Err(CustomError::InvalidIssuedProof)
                
            }
        }
    }
}





