use std::io::Cursor;

use serde::{Deserialize, Serialize};

use crate::{jpt::{payloads::{Payloads, PayloadType}, claims::Claims}, errors::CustomError, encoding::{SerializationType, base64url_encode_serializable, base64url_encode}, jwk::key::Jwk, jpa::{algs::ProofAlgorithm, bbs_plus::BBSplusAlgorithm}};

use super::{header::{IssuerProtectedHeader, PresentationProtectedHeader}, issued::JwpIssued};

/// Takes the result of a rsplit and ensure we only get 4 parts (JwpPresented)
/// Errors if we don't
macro_rules! expect_four {
    ($iter:expr) => {{
        let mut i = $iter;
        match (i.next(), i.next(), i.next(), i.next()) {
            (Some(first), Some(second), Some(third), Some(fourth)) => (first, second, third, fourth),
            _ => return Err(new_error(ErrorKind::InvalidToken)),
        }
    }};
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct JwpPresented {
    issuer_protected_header: IssuerProtectedHeader,
    presentation_protected_header: PresentationProtectedHeader,
    payloads: Payloads,
    issuer_proof: Vec<u8>,
    proof: Option<Vec<u8>>
}

impl JwpPresented {

    pub fn new(issuer_protected_header: IssuerProtectedHeader, presentation_protected_header: PresentationProtectedHeader, payloads: Payloads, issuer_proof: Vec<u8>) -> Self {
        Self { issuer_protected_header, presentation_protected_header, payloads, proof: None, issuer_proof: issuer_proof}
    }

    pub fn encode(&self, serialization: SerializationType, key: &Jwk) -> Result<String, CustomError> {
        let encoded_issuer_header = base64url_encode_serializable(&self.issuer_protected_header);
        let encoded_presentation_header = base64url_encode_serializable(&self.presentation_protected_header);

        let proof = Self::generate_proof(self.presentation_protected_header.alg, key, &self.issuer_proof, &encoded_issuer_header, &encoded_presentation_header, &self.payloads)?;

        let jwp = Self::serialize(serialization, &encoded_presentation_header, &encoded_issuer_header, &self.payloads, &proof);
        
        Ok(jwp)
    }


    pub fn decode() {
        todo!()
    }


    pub fn set_disclosed(&mut self, index: usize, disclosed: bool) -> Result<(), CustomError>{
        self.payloads.set_disclosed(index, disclosed)
    }

    pub fn get_issuer_protected_header(&self) -> &IssuerProtectedHeader {
        &self.issuer_protected_header
    }

    pub fn get_presentation_protected_header(&self) -> &PresentationProtectedHeader {
        &self.presentation_protected_header
    }

    pub fn get_claims(&self) -> &Option<Claims>{
        &self.issuer_protected_header.claims
    }

    pub fn get_payloads(&self) -> &Payloads {
        &self.payloads
    }

    pub fn get_proof(&self) -> &Option<Vec<u8>> {
        &self.proof
    }

    fn generate_proof(alg: ProofAlgorithm, key: &Jwk, issuer_proof: &[u8], encoded_issuer_header: &str, encoded_presentation_header: &str, payloads: &Payloads) -> Result<String, CustomError> {
        let proof = match alg {
            ProofAlgorithm::BLS12381_SHA256_PROOF | ProofAlgorithm::BLS12381_SHAKE256_PROOF => {
                base64url_encode(BBSplusAlgorithm::generate_presentation_proof(alg, issuer_proof, payloads, key, encoded_issuer_header, encoded_presentation_header)?)
            },
            ProofAlgorithm::SU_ES256 => todo!(),
            ProofAlgorithm::MAC_H256 => todo!(),
            ProofAlgorithm::MAC_H384 => todo!(),
            ProofAlgorithm::MAC_H512 => todo!(),
            ProofAlgorithm::MAC_K25519 => todo!(),
            ProofAlgorithm::MAC_K448 => todo!(),
            ProofAlgorithm::MAC_H256K => todo!(),
            ProofAlgorithm::BLS12381_SHA256  => panic!("This is valid only in issued JWPs"),
            ProofAlgorithm::BLS12381_SHAKE256 => todo!("This is valid only in issued JWPs"),
        };

        Ok(proof)
    }

    fn verify_proof() {
        todo!()
    }

    fn serialize(serialization: SerializationType, encoded_presentation_header: &str, encoded_issuer_header: &str, payloads: &Payloads, proof: &str) -> String {
        let jwp = match serialization {
            SerializationType::COMPACT => {
                let encoded_payloads = payloads.0.iter().map(|p| {
                    if p.1 == PayloadType::Undisclosed {
                        "".to_string()
                    } else {
                        p.0.clone()
                    }
                })
                .collect::<Vec<String>>()
                .join("~");

                

                format!("{}.{}.{}.{}", encoded_presentation_header, encoded_issuer_header, encoded_payloads, proof)
                
            },
            SerializationType::JSON => todo!(),
        };

        jwp
    }
}