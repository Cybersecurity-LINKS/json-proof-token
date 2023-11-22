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

use crate::{jpt::{payloads::{Payloads, PayloadType}, claims::Claims}, errors::CustomError, encoding::{SerializationType, base64url_encode_serializable, base64url_encode, Base64UrlDecodedSerializable, base64url_decode}, jwk::key::Jwk, jpa::{algs::ProofAlgorithm, bbs::{BBSAlgorithm, BBSImplementation}, su::{SUAlgorithm, SUImplementation}, mac::{MACAlgorithm, MACImplementation}}};

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
pub struct JwpPresented <B: BBSAlgorithm, S: SUAlgorithm, M: MACAlgorithm>{
    issuer_protected_header: Option<IssuerProtectedHeader>,
    presentation_protected_header: Option<PresentationProtectedHeader>,
    payloads: Option<Payloads>,
    proof: Option<Vec<u8>>,


    #[serde(skip_serializing)]
    bbs: BBSImplementation<B>,
    #[serde(skip_serializing)]
    su: SUImplementation<S>,
    #[serde(skip_serializing)]
    mac: MACImplementation<M>
}

impl <B: BBSAlgorithm, S: SUAlgorithm, M: MACAlgorithm> JwpPresented <B, S, M> {

    pub fn new(bbs: BBSImplementation<B>, su: SUImplementation<S>, mac: MACImplementation<M>) -> Self{
        Self { 
            issuer_protected_header: None,
            presentation_protected_header: None,
            payloads: None, 
            proof: None, 
            bbs: bbs, 
            su: su, 
            mac: mac 
        }
    }

    
    pub fn get_issuer_protected_header(&self) -> Option<&IssuerProtectedHeader> {
        self.issuer_protected_header.as_ref()
    }

    // Setter for issuer_protected_header
    pub fn set_issuer_protected_header(&mut self, value: &IssuerProtectedHeader) {
        self.issuer_protected_header = Some(value.clone());
    }

        
    pub fn get_presentation_protected_header(&self) -> Option<&PresentationProtectedHeader> {
        self.presentation_protected_header.as_ref()
    }

    // Setter for issuer_protected_header
    pub fn set_presentation_protected_header(&mut self, value: PresentationProtectedHeader) {
        self.presentation_protected_header = Some(value);
    }

    // Getter for payloads
    pub fn get_payloads(&self) -> Option<&Payloads> {
        self.payloads.as_ref()
    }

    // Setter for payloads
    pub fn set_payloads(&mut self, value: &Payloads) {
        self.payloads = Some(value.clone());
    }

    // Getter for proof
    pub fn get_proof(&self) -> Option<&[u8]> {
        self.proof.as_deref()
    }

    fn set_proof(&mut self, proof: Vec<u8>) {
        self.proof = Some(proof);
    }


    pub fn set_disclosed(&mut self, index: usize, disclosed: bool) -> Result<(), CustomError> {
        if let Some(payloads) = self.payloads.as_mut() {
            payloads.set_disclosed(index, disclosed);
            Ok(())
        } else {
            Err(CustomError::MissingParameter("payloads is None".to_owned()))
        }
    }

    pub fn get_claims(&self) -> Option<&Claims> {
        self.issuer_protected_header
            .as_ref() // Get a reference to the Option<IssuerProtectedHeader>
            .and_then(|header| header.claims.as_ref()) // Get a reference to the Option<Claims> inside IssuerProtectedHeader
    }



    pub fn encode(&self, serialization: SerializationType, key: &Jwk, issuer_proof: &[u8]) -> Result<String, CustomError> {
        // let encoded_issuer_header = base64url_encode_serializable(&self.issuer_protected_header);
        // let encoded_presentation_header = base64url_encode_serializable(&self.presentation_protected_header);


        // Check if issuer_protected_header is Some
        let issuer_protected_header = match &self.issuer_protected_header {
            Some(header) => header,
            None => return Err(CustomError::MissingParameter("issuer_protected_header is None".to_owned())),
        };

        // Check if presentation_protected_header is Some
        let presentation_protected_header = match &self.presentation_protected_header {
            Some(header) => header,
            None => return Err(CustomError::MissingParameter("presentation_protected_header is None".to_owned())),
        };

        // Check if payloads is Some
        let payloads = match &self.payloads {
            Some(payloads) => payloads,
            None => return Err(CustomError::MissingParameter("payloads is None".to_owned())),
        };



        let issuer_header_oct = serde_json::to_vec(issuer_protected_header).unwrap();
        let presentation_header_oct = serde_json::to_vec(presentation_protected_header).unwrap();

        let proof = Self::generate_proof(presentation_protected_header.alg, key, &issuer_proof, &issuer_header_oct, &presentation_header_oct, payloads)?;

        let jwp = Self::serialize(serialization, &presentation_header_oct, &issuer_header_oct, payloads, &proof);
        
        Ok(jwp)
    }


    pub fn decode(&mut self, encoded_jwp: String, serialization: SerializationType, key: &Jwk) -> Result<(), CustomError> {
        match serialization {
            SerializationType::COMPACT => {
                let (encoded_presentation_protected_header, encoded_issuer_protected_header, encoded_payloads, encoded_proof) = expect_four!(encoded_jwp.splitn(4, '.'));
                //TODO: this needs to be checked because doesn't return an error if the value is not deserializable into an IssuerProtectedHeader struct
                let presentation_protected_header: PresentationProtectedHeader = Base64UrlDecodedSerializable::from_serializable_values(encoded_presentation_protected_header).deserialize::<PresentationProtectedHeader>();
                let issuer_protected_header: IssuerProtectedHeader = Base64UrlDecodedSerializable::from_serializable_values(encoded_issuer_protected_header).deserialize::<IssuerProtectedHeader>();
                let payloads = Payloads(encoded_payloads.splitn(issuer_protected_header.claims.as_ref().unwrap().0.len(), "~").map(|v| {
                    if v == "" {
                        (serde_json::Value::Null, PayloadType::Undisclosed)
                    } else {
                        (serde_json::from_slice(&base64url_decode(v)).unwrap(), PayloadType::Disclosed)
                    }
                }).collect());

                let proof = base64url_decode(encoded_proof);
                let issuer_header_oct = serde_json::to_vec(&issuer_protected_header).unwrap();
                let presentation_header_oct = serde_json::to_vec(&presentation_protected_header).unwrap();

                match Self::verify_proof(presentation_protected_header.alg, key, &proof, &presentation_header_oct, &issuer_header_oct, &payloads) {
                    Ok(_) => {
                        println!("Presented Proof Valid!!!!");
                        self.set_issuer_protected_header(&issuer_protected_header);
                        self.set_presentation_protected_header(presentation_protected_header);
                        self.set_payloads(&payloads);
                        self.set_proof(proof);
                        Ok(())
                    },
                    Err(e) => Err(e),
                }            
            },
            SerializationType::JSON => todo!()
        }
    }



    fn generate_proof(alg: ProofAlgorithm, key: &Jwk, issuer_proof: &[u8], issuer_header_oct: &[u8], presentation_header_oct: &[u8], payloads: &Payloads) -> Result<String, CustomError> {
        let proof = match alg {
            ProofAlgorithm::BLS12381_SHA256_PROOF | ProofAlgorithm::BLS12381_SHAKE256_PROOF => {
                base64url_encode(alg.bbs_generate_presentation_proof::<B>( issuer_proof, payloads, key, issuer_header_oct, presentation_header_oct)?)
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
        // let proof = base64url_encode(alg.generate_presentation_proof( issuer_proof, payloads, key, issuer_header_oct, presentation_header_oct)?);
        Ok(proof)
    }

    fn verify_proof(alg: ProofAlgorithm, key: &Jwk, proof: &[u8], presentation_header_oct: &[u8], issuer_header_oct: &[u8], payloads: &Payloads) -> Result<(), CustomError> {
        let check = match alg {
            ProofAlgorithm::BLS12381_SHA256_PROOF | ProofAlgorithm::BLS12381_SHAKE256_PROOF => {
                alg.bbs_verify_presentation_proof::<B>(key, proof, presentation_header_oct, issuer_header_oct, payloads)
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

        // let check = alg.verify_presentation_proof(key, proof, presentation_header_oct, issuer_header_oct, payloads);
        check
    }

    fn serialize(serialization: SerializationType, presentation_header_oct: &[u8], issuer_header_oct: &[u8], payloads: &Payloads, proof: &str) -> String {
        let encoded_issuer_header = base64url_encode(issuer_header_oct);
        let encoded_presentation_header = base64url_encode(presentation_header_oct);
        
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

                

                format!("{}.{}.{}.{}", encoded_presentation_header, encoded_issuer_header, encoded_payloads, proof)
                
            },
            SerializationType::JSON => todo!(),
        };

        jwp
    }
}