use serde::{Deserialize, Serialize, ser::SerializeMap};

use crate::{jpt::{payloads::{Payloads, PayloadType}, claims::Claims}, encoding::{base64url_encode, base64url_encode_serializable, SerializationType, Base64UrlDecodedSerializable, self, base64url_decode}, jwk::key::Jwk, jpa::{bbs_plus::BBSplusAlgorithm, algs::ProofAlgorithm}, errors::CustomError};

use super::{header::{IssuerProtectedHeader, PresentationProtectedHeader}, presented::JwpPresented};


/// Takes the result of a rsplit and ensure we only get 3 parts (JwpIssued)
/// Errors if we don't
macro_rules! expect_three {
    ($iter:expr) => {{
        let mut i = $iter;
        match (i.next(), i.next(), i.next()) {
            (Some(first), Some(second), Some(third)) => (first, second, third),
            _ => return Err(CustomError::InvalidIssuedJwp),
        }
    }};
}


#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct JwpIssued {
    issuer_protected_header: IssuerProtectedHeader,
    payloads: Payloads,
    proof: Option<Vec<u8>>
}

impl JwpIssued {

    pub fn new(issuer_protected_header: IssuerProtectedHeader, payloads: Payloads) -> Self{
        Self { issuer_protected_header, payloads, proof: None }
    }

    
    pub fn encode(&self, serialization: SerializationType, key: &Jwk) -> Result<String, CustomError> {
        let encoded_issuer_header = base64url_encode_serializable(&self.issuer_protected_header);

        let proof = Self::generate_proof(self.issuer_protected_header.alg, key, &encoded_issuer_header, &self.payloads)?;

        let jwp = Self::serialize(serialization, &encoded_issuer_header, &self.payloads, &proof);
        
        Ok(jwp)
    }

    pub fn decode(encoded_jwp: String, serialization: SerializationType, key: &Jwk) -> Result<Self, CustomError>{
        match serialization {
            SerializationType::COMPACT => {
                let (encoded_issuer_protected_header, encoded_payloads, encoded_proof) = expect_three!(encoded_jwp.splitn(3, '.')); 
                println!("{} || {} || {}", encoded_issuer_protected_header, encoded_payloads, encoded_proof);
                let issuer_protected_header: IssuerProtectedHeader = Base64UrlDecodedSerializable::from_serializable_values(encoded_issuer_protected_header).deserialize::<IssuerProtectedHeader>();
                let payloads = Payloads(encoded_payloads.splitn(issuer_protected_header.claims.as_ref().unwrap().0.len(), "~").map(|v| {
                    if v == "" {
                        ("".to_string(), PayloadType::Undisclosed)
                    } else {
                        (v.to_string(), PayloadType::Disclosed)
                    }
                }).collect());

                match Self::verify_proof(issuer_protected_header.alg, key, encoded_proof, encoded_issuer_protected_header, &payloads) {
                    Ok(_) => {
                        println!("Issued Proof Valid!!!!");
                        Ok(Self{issuer_protected_header, payloads, proof: Some(base64url_decode(encoded_proof))})
                    },
                    Err(e) => Err(e),
                }            
            },
            SerializationType::JSON => todo!()
        }
        
        // Base64UrlDecodedSerializable::deserialize(&'a self)
    }


    pub fn get_issuer_protected_header(&self) -> &IssuerProtectedHeader {
        &self.issuer_protected_header
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

    pub fn present(&self, presentation_header: PresentationProtectedHeader) -> JwpPresented {
        JwpPresented::new(self.issuer_protected_header.clone(), presentation_header, self.payloads.clone(), self.proof.as_ref().unwrap().clone())
    }

    fn generate_proof(alg: ProofAlgorithm, key: &Jwk, encoded_issuer_header: &str,  payloads: &Payloads) -> Result<String, CustomError>{
        let proof = match alg {
            ProofAlgorithm::BLS12381_SHA256 | ProofAlgorithm::BLS12381_SHAKE256 => {
                base64url_encode(BBSplusAlgorithm::generate_issuer_proof(alg, payloads, key, encoded_issuer_header)?)
            },
            ProofAlgorithm::SU_ES256 => todo!(),
            ProofAlgorithm::MAC_H256 => todo!(),
            ProofAlgorithm::MAC_H384 => todo!(),
            ProofAlgorithm::MAC_H512 => todo!(),
            ProofAlgorithm::MAC_K25519 => todo!(),
            ProofAlgorithm::MAC_K448 => todo!(),
            ProofAlgorithm::MAC_H256K => todo!(),
            ProofAlgorithm::BLS12381_SHA256_PROOF => panic!("This is valid only in presented JWPs"),
            ProofAlgorithm::BLS12381_SHAKE256_PROOF => todo!("This is valid only in presented JWPs"),
        };

        Ok(proof)
    }

    fn verify_proof(alg: ProofAlgorithm, key: &Jwk, proof: &str, encoded_issuer_header: &str, payloads: &Payloads) -> Result<(), CustomError> {
        let check = match alg {
            ProofAlgorithm::BLS12381_SHA256 | ProofAlgorithm::BLS12381_SHAKE256 => {
                BBSplusAlgorithm::verify_issuer_proof(alg,  &key, proof, &encoded_issuer_header, payloads)
            },
            ProofAlgorithm::SU_ES256 => todo!(),
            ProofAlgorithm::MAC_H256 => todo!(),
            ProofAlgorithm::MAC_H384 => todo!(),
            ProofAlgorithm::MAC_H512 => todo!(),
            ProofAlgorithm::MAC_K25519 => todo!(),
            ProofAlgorithm::MAC_K448 => todo!(),
            ProofAlgorithm::MAC_H256K => todo!(),
            ProofAlgorithm::BLS12381_SHA256_PROOF => panic!("This is valid only in presented JWPs"),
            ProofAlgorithm::BLS12381_SHAKE256_PROOF => panic!("This is valid only in presented JWPs"),
        };

        check
    }

    fn serialize(serialization: SerializationType, encoded_issuer_header: &str, payloads: &Payloads, proof: &str) -> String {
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

                

                format!("{}.{}.{}", encoded_issuer_header, encoded_payloads, proof)
                
            },
            SerializationType::JSON => todo!(),
        };

        jwp
    }
}