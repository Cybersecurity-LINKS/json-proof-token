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
        // let encoded_issuer_header = base64url_encode_serializable(&self.issuer_protected_header);

        let issuer_header_oct = serde_json::to_vec(&self.issuer_protected_header).unwrap();

        let proof = Self::generate_proof(self.issuer_protected_header.alg, key, &issuer_header_oct, &self.payloads)?;

        let jwp = Self::serialize(serialization, &issuer_header_oct, &self.payloads, &proof);
        
        Ok(jwp)
    }

    pub fn decode(encoded_jwp: String, serialization: SerializationType, key: &Jwk) -> Result<Self, CustomError>{
        match serialization {
            SerializationType::COMPACT => {
                let (encoded_issuer_protected_header, encoded_payloads, encoded_proof) = expect_three!(encoded_jwp.splitn(3, '.')); 
                //TODO: this needs to be checked because doesn't return an error if the value is not deserializable into an IssuerProtectedHeader struct
                let issuer_protected_header: IssuerProtectedHeader = Base64UrlDecodedSerializable::from_serializable_values(encoded_issuer_protected_header).deserialize::<IssuerProtectedHeader>();
                
                //TODO: this could not have much sense for now (maybe useful to handle blind signatures?)
                let payloads = Payloads(encoded_payloads.splitn(issuer_protected_header.claims.as_ref().unwrap().0.len(), "~").map(|v| {
                    if v == "" {
                        (serde_json::Value::Null, PayloadType::Undisclosed)
                    } else {
                        (serde_json::from_slice(&base64url_decode(v)).unwrap(), PayloadType::Disclosed)
                    }
                }).collect());

                let proof = base64url_decode(encoded_proof);
                let issuer_header_oct = serde_json::to_vec(&issuer_protected_header).unwrap();

                match Self::verify_proof(issuer_protected_header.alg, key, &proof, &issuer_header_oct, &payloads) {
                    Ok(_) => {
                        println!("Issued Proof Valid!!!!");
                        Ok(Self{issuer_protected_header, payloads, proof: Some(proof)})
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

    pub fn get_proof(&self) -> Option<&Vec<u8>> {
        self.proof.as_ref()
    }

    pub fn present(&self, serialization: SerializationType, key: &Jwk, presentation_header: PresentationProtectedHeader) -> Result<String, CustomError> {
        let jwp = JwpPresented::new(self.issuer_protected_header.clone(), presentation_header, self.payloads.clone());
        jwp.encode(serialization, key, self.get_proof().unwrap())

    }

    fn generate_proof(alg: ProofAlgorithm, key: &Jwk, issuer_header_oct: &[u8],  payloads: &Payloads) -> Result<String, CustomError>{
        let proof = match alg {
            ProofAlgorithm::BLS12381_SHA256 | ProofAlgorithm::BLS12381_SHAKE256 => {
                base64url_encode(BBSplusAlgorithm::generate_issuer_proof(alg, payloads, key, issuer_header_oct)?)
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

    fn verify_proof(alg: ProofAlgorithm, key: &Jwk, proof: &[u8], issuer_header_oct: &[u8], payloads: &Payloads) -> Result<(), CustomError> {
        let check = match alg {
            ProofAlgorithm::BLS12381_SHA256 | ProofAlgorithm::BLS12381_SHAKE256 => {
                BBSplusAlgorithm::verify_issuer_proof(alg,  &key, proof, issuer_header_oct, payloads)
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

    fn serialize(serialization: SerializationType, issuer_header_oct: &[u8], payloads: &Payloads, proof: &str) -> String {
        let encoded_issuer_header = base64url_encode(issuer_header_oct);
        
        let jwp = match serialization {
            SerializationType::COMPACT => {
                let encoded_payloads = payloads.0.iter().map(|p| {
                    if p.1 == PayloadType::Undisclosed {
                        "".to_string()
                    } else {
                        base64url_encode_serializable(&p.0)
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