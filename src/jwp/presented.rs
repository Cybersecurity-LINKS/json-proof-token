use std::io::Cursor;

use serde::{Deserialize, Serialize};

use crate::{jpt::{payloads::{Payloads, PayloadType}, claims::Claims}, errors::CustomError, encoding::{SerializationType, base64url_encode_serializable, base64url_encode, Base64UrlDecodedSerializable, base64url_decode}, jwk::key::Jwk, jpa::{algs::ProofAlgorithm, bbs_plus::BBSplusAlgorithm}};

use super::{header::{IssuerProtectedHeader, PresentationProtectedHeader}, issued::JwpIssued};

/// Takes the result of a rsplit and ensure we only get 4 parts (JwpPresented)
/// Errors if we don't
macro_rules! expect_four {
    ($iter:expr) => {{
        let mut i = $iter;
        match (i.next(), i.next(), i.next(), i.next()) {
            (Some(first), Some(second), Some(third), Some(fourth)) => (first, second, third, fourth),
            _ => return Err(CustomError::InvalidPresentedJwp),
        }
    }};
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct JwpPresented {
    issuer_protected_header: IssuerProtectedHeader,
    presentation_protected_header: PresentationProtectedHeader,
    payloads: Payloads,
    proof: Option<Vec<u8>>
}

impl JwpPresented {

    pub fn new(issuer_protected_header: IssuerProtectedHeader, presentation_protected_header: PresentationProtectedHeader, payloads: Payloads) -> Self {
        Self { issuer_protected_header, presentation_protected_header, payloads, proof: None}
    }

    pub fn encode(&self, serialization: SerializationType, key: &Jwk, issuer_proof: &[u8]) -> Result<String, CustomError> {
        let encoded_issuer_header = base64url_encode_serializable(&self.issuer_protected_header);
        let encoded_presentation_header = base64url_encode_serializable(&self.presentation_protected_header);

        let proof = Self::generate_proof(self.presentation_protected_header.alg, key, &issuer_proof, &encoded_issuer_header, &encoded_presentation_header, &self.payloads)?;

        let jwp = Self::serialize(serialization, &encoded_presentation_header, &encoded_issuer_header, &self.payloads, &proof);
        
        Ok(jwp)
    }


    pub fn decode(encoded_jwp: String, serialization: SerializationType, key: &Jwk) -> Result<Self, CustomError> {
        match serialization {
            SerializationType::COMPACT => {
                let (encoded_presentation_protected_header, encoded_issuer_protected_header, encoded_payloads, encoded_proof) = expect_four!(encoded_jwp.splitn(4, '.'));
                let presentation_protected_header: PresentationProtectedHeader = Base64UrlDecodedSerializable::from_serializable_values(encoded_issuer_protected_header).deserialize::<PresentationProtectedHeader>();
                let issuer_protected_header: IssuerProtectedHeader = Base64UrlDecodedSerializable::from_serializable_values(encoded_issuer_protected_header).deserialize::<IssuerProtectedHeader>();
                let payloads = Payloads(encoded_payloads.splitn(issuer_protected_header.claims.as_ref().unwrap().0.len(), "~").map(|v| {
                    if v == "" {
                        ("".to_string(), PayloadType::Undisclosed)
                    } else {
                        (v.to_string(), PayloadType::Disclosed)
                    }
                }).collect());

                match Self::verify_proof(presentation_protected_header.alg, key, encoded_proof, encoded_presentation_protected_header, encoded_issuer_protected_header, &payloads) {
                    Ok(_) => {
                        println!("Issued Proof Valid!!!!");
                        Ok(Self{issuer_protected_header, payloads, proof: Some(base64url_decode(encoded_proof)), presentation_protected_header})
                    },
                    Err(e) => Err(e),
                }            
            },
            SerializationType::JSON => todo!()
        }
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

    fn verify_proof(alg: ProofAlgorithm, key: &Jwk, proof: &str, encoded_presentation_header: &str, encoded_issuer_header: &str, payloads: &Payloads) -> Result<(), CustomError> {
        let check = match alg {
            ProofAlgorithm::BLS12381_SHA256_PROOF | ProofAlgorithm::BLS12381_SHAKE256_PROOF => {
                BBSplusAlgorithm::verify_presentation_proof(alg,  &key, proof, encoded_presentation_header, encoded_issuer_header, payloads)
            },
            ProofAlgorithm::SU_ES256 => todo!(),
            ProofAlgorithm::MAC_H256 => todo!(),
            ProofAlgorithm::MAC_H384 => todo!(),
            ProofAlgorithm::MAC_H512 => todo!(),
            ProofAlgorithm::MAC_K25519 => todo!(),
            ProofAlgorithm::MAC_K448 => todo!(),
            ProofAlgorithm::MAC_H256K => todo!(),
            ProofAlgorithm::BLS12381_SHA256 => panic!("This is valid only in issued JWPs"),
            ProofAlgorithm::BLS12381_SHAKE256 => panic!("This is valid only in issued JWPs"),
        };

        check
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