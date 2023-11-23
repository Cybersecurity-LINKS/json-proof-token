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
use zkryptium::{bbsplus::{keys::{BBSplusPublicKey, BBSplusSecretKey}, signature::BBSplusSignature, proof::BBSplusPoKSignature}, utils::message::BBSplusMessage, schemes::{generics::{Signature, PoKSignature}, algorithms::{BBS_BLS12381_SHA256, BBS_BLS12381_SHAKE256, Scheme}}, keys::pair::KeyPair};

use crate::{jwk::{key::Jwk, utils::{check_alg_curve_compatibility}, alg_parameters::{Algorithm, JwkAlgorithmParameters}}, jwp::header::IssuerProtectedHeader, errors::CustomError, encoding::base64url_decode, jpt::payloads::Payloads};

use super::algs::ProofAlgorithm;



#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct BBSImplementation<B: BBSAlgorithm> (B);

impl <B: BBSAlgorithm>BBSImplementation<B> {
    pub fn new(implementation: B) -> BBSImplementation<B> {
        Self(implementation)
    }
}

impl Default for BBSImplementation<ZkryptiumImplementation> {
    fn default() -> Self {
        Self(ZkryptiumImplementation)
    }
}

//TODO: define constant values for sk, pk, signature length
pub trait BBSAlgorithm
{


    fn keygen_sha256() -> Result<([u8; 32], [u8; 96]), Box<dyn std::error::Error>>;
    fn keygen_shake256() -> Result<([u8; 32], [u8; 96]), Box<dyn std::error::Error>>;
    fn sign_bls12381_sha256(sk: &[u8], pk: &[u8], header: &[u8], messages: Vec<Vec<u8>>) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    fn sign_bls12381_shake256(sk: &[u8], pk: &[u8], header: &[u8], messages: Vec<Vec<u8>>) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    fn verify_bls12381_sha256(pk: &[u8], signature: &[u8], header: &[u8], messages: Vec<Vec<u8>>) -> Result<(), Box<dyn std::error::Error>>;
    fn verify_bls12381_shake256(pk: &[u8], signature: &[u8], header: &[u8], messages: Vec<Vec<u8>>) -> Result<(), Box<dyn std::error::Error>>;
    fn proofgen_bls12381_sha256(pk: &[u8], signature: &[u8], header: &[u8], ph: &[u8], messages: Vec<Vec<u8>>, disclosed_indexes: &[usize]) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    fn proofgen_bls12381_shake256(pk: &[u8], signature: &[u8], header: &[u8], ph: &[u8], messages: Vec<Vec<u8>>, disclosed_indexes: &[usize]) -> Result<Vec<u8>, Box<dyn std::error::Error>>;
    fn proofverify_bls12381_sha256(pk: &[u8], proof: &[u8], header: &[u8], ph: &[u8], disclosed_messages: Vec<Vec<u8>>, disclosed_indexes: &[usize]) -> Result<(), Box<dyn std::error::Error>>;
    fn proofverify_bls12381_shake256(pk: &[u8], proof: &[u8], header: &[u8], ph: &[u8], disclosed_messages: Vec<Vec<u8>>, disclosed_indexes: &[usize]) -> Result<(), Box<dyn std::error::Error>>;
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct ZkryptiumImplementation;

impl BBSAlgorithm for ZkryptiumImplementation {

    fn keygen_sha256() -> Result<([u8; 32], [u8; 96]), Box<dyn std::error::Error>> {
        let keypair = KeyPair::<BBS_BLS12381_SHA256>::generate(None, None);
        Ok((keypair.private_key().to_bytes(), keypair.public_key().to_bytes()))
    }

    fn keygen_shake256() -> Result<([u8; 32], [u8; 96]), Box<dyn std::error::Error>> {
        let keypair = KeyPair::<BBS_BLS12381_SHAKE256>::generate(None, None);
        Ok((keypair.private_key().to_bytes(), keypair.public_key().to_bytes()))
    }

    fn sign_bls12381_sha256(sk: &[u8], pk: &[u8], header: &[u8], messages: Vec<Vec<u8>>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let pk = BBSplusPublicKey::from_bytes(&pk);
        let sk = BBSplusSecretKey::from_bytes(&sk);
        let messages: Vec<BBSplusMessage> = messages
            .iter()
            .map(|p| BBSplusMessage::map_message_to_scalar_as_hash::<<BBS_BLS12381_SHA256 as Scheme>::Ciphersuite>(p, None))
            .collect();

        let signature = Signature::<BBS_BLS12381_SHA256>::sign(Some(&messages), &sk, &pk, None, Some(header)).to_bytes();
        Ok(signature.to_vec()) //TODO: maybe change the return value to match the exact slice length
    }

    fn sign_bls12381_shake256(sk: &[u8], pk: &[u8], header: &[u8], messages: Vec<Vec<u8>>) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let pk = BBSplusPublicKey::from_bytes(pk);
        let sk = BBSplusSecretKey::from_bytes(sk);
        let messages: Vec<BBSplusMessage> = messages
            .iter()
            .map(|p| BBSplusMessage::map_message_to_scalar_as_hash::<<BBS_BLS12381_SHAKE256 as Scheme>::Ciphersuite>(p, None))
            .collect();

        let signature = Signature::<BBS_BLS12381_SHAKE256>::sign(Some(&messages), &sk, &pk, None, Some(header)).to_bytes();
        Ok(signature.to_vec())
    }

    fn verify_bls12381_sha256(pk: &[u8], signature: &[u8], header: &[u8], messages: Vec<Vec<u8>>) -> Result<(), Box<dyn std::error::Error>> {
        let pk = BBSplusPublicKey::from_bytes(pk);
        let signature = BBSplusSignature::from_bytes(signature.try_into().unwrap()).unwrap();
        let messages: Vec<BBSplusMessage> = messages
            .iter()
            .map(|p| BBSplusMessage::map_message_to_scalar_as_hash::<<BBS_BLS12381_SHA256 as Scheme>::Ciphersuite>(p, None))
            .collect();
        let signature = Signature::<BBS_BLS12381_SHA256>::BBSplus(signature);
        match signature.verify(&pk, Some(&messages), None, Some(header)) {
            true => Ok(()), 
            false => Err(Box::new(CustomError::InvalidIssuedProof))
        }
    }

    fn verify_bls12381_shake256(pk: &[u8], signature: &[u8], header: &[u8], messages: Vec<Vec<u8>>) -> Result<(), Box<dyn std::error::Error>> {
        let pk = BBSplusPublicKey::from_bytes(pk);
        let signature = BBSplusSignature::from_bytes(signature.try_into().unwrap()).unwrap();
        let messages: Vec<BBSplusMessage> = messages
            .iter()
            .map(|p| BBSplusMessage::map_message_to_scalar_as_hash::<<BBS_BLS12381_SHAKE256 as Scheme>::Ciphersuite>(p, None))
            .collect();
        let signature = Signature::<BBS_BLS12381_SHAKE256>::BBSplus(signature);
        match signature.verify(&pk, Some(&messages), None, Some(header)) {
            true => Ok(()),
            false => Err(Box::new(CustomError::InvalidIssuedProof))
        }
    }

    fn proofgen_bls12381_sha256(pk: &[u8], signature: &[u8], header: &[u8], ph: &[u8], messages: Vec<Vec<u8>>, disclosed_indexes: &[usize]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let pk = BBSplusPublicKey::from_bytes(pk);
        let signature = BBSplusSignature::from_bytes(signature.try_into().unwrap()).unwrap();
        let messages: Vec<BBSplusMessage> = messages
            .iter()
            .map(|p| BBSplusMessage::map_message_to_scalar_as_hash::<<BBS_BLS12381_SHA256 as Scheme>::Ciphersuite>(p, None))
            .collect();
        let proof = PoKSignature::<BBS_BLS12381_SHA256>::proof_gen(&signature, &pk, Some(&messages), None, Some(&disclosed_indexes), Some(header), Some(ph), None).to_bytes();
        Ok(proof)
    }

    fn proofgen_bls12381_shake256(pk: &[u8], signature: &[u8], header: &[u8], ph: &[u8], messages: Vec<Vec<u8>>, disclosed_indexes: &[usize]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let pk = BBSplusPublicKey::from_bytes(pk);
        let signature = BBSplusSignature::from_bytes(signature.try_into().unwrap()).unwrap();
        let messages: Vec<BBSplusMessage> = messages
            .iter()
            .map(|p| BBSplusMessage::map_message_to_scalar_as_hash::<<BBS_BLS12381_SHAKE256 as Scheme>::Ciphersuite>(p, None))
            .collect();
        let proof = PoKSignature::<BBS_BLS12381_SHAKE256>::proof_gen(&signature, &pk, Some(&messages), None, Some(&disclosed_indexes), Some(header), Some(ph), None).to_bytes();
        Ok(proof)
    }

    fn proofverify_bls12381_sha256(pk: &[u8], proof: &[u8], header: &[u8], ph: &[u8], disclosed_messages: Vec<Vec<u8>>, disclosed_indexes: &[usize]) -> Result<(), Box<dyn std::error::Error>> {
        let pk = BBSplusPublicKey::from_bytes(pk);
        let proof = BBSplusPoKSignature::from_bytes(proof.try_into().unwrap());
        let disclosed_messages: Vec<BBSplusMessage> = disclosed_messages
            .iter()
            .map(|p| BBSplusMessage::map_message_to_scalar_as_hash::<<BBS_BLS12381_SHA256 as Scheme>::Ciphersuite>(p, None))
            .collect();
        let proof = PoKSignature::<BBS_BLS12381_SHA256>::BBSplus(proof);
        match proof.proof_verify(&pk, Some(&disclosed_messages), None, Some(&disclosed_indexes), Some(header), Some(ph)) {
            true => Ok(()),
            false => Err(Box::new(CustomError::InvalidPresentedProof)),
        }

    }

    fn proofverify_bls12381_shake256(pk: &[u8], proof: &[u8], header: &[u8], ph: &[u8], disclosed_messages: Vec<Vec<u8>>, disclosed_indexes: &[usize]) -> Result<(), Box<dyn std::error::Error>> {
        let pk = BBSplusPublicKey::from_bytes(pk);
        let proof = BBSplusPoKSignature::from_bytes(proof.try_into().unwrap());
        let disclosed_messages: Vec<BBSplusMessage> = disclosed_messages
            .iter()
            .map(|p| BBSplusMessage::map_message_to_scalar_as_hash::<<BBS_BLS12381_SHAKE256 as Scheme>::Ciphersuite>(p, None))
            .collect();
        let proof = PoKSignature::<BBS_BLS12381_SHAKE256>::BBSplus(proof);
        match proof.proof_verify(&pk, Some(&disclosed_messages), None, Some(&disclosed_indexes), Some(header), Some(ph)) {
            true => Ok(()),
            false => Err(Box::new(CustomError::InvalidPresentedProof)),
        }
    }

}