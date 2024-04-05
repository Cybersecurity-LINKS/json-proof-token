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

use crate::{
    encoding::{
        base64url_decode, base64url_encode, base64url_encode_serializable,
        SerializationType,
    },
    errors::CustomError,
    jpa::{algs::PresentationProofAlgorithm, bbs_plus::BBSplusAlgorithm},
    jpt::{
        claims::Claims,
        payloads::{PayloadType, Payloads},
    },
    jwk::key::Jwk,
};

use super::{
    header::{IssuerProtectedHeader, PresentationProtectedHeader},
    issued::JwpIssued,
};

/// Takes the result of a rsplit and ensure we only get 4 parts (JwpPresented)
/// Errors if we don't
macro_rules! expect_four {
    ($iter:expr) => {{
        let mut i = $iter;
        match (i.next(), i.next(), i.next(), i.next()) {
            (Some(first), Some(second), Some(third), Some(fourth)) => {
                (first, second, third, fourth)
            }
            _ => return Err(CustomError::InvalidPresentedJwp),
        }
    }};
}

/// Used to build a new JSON Web Proof in the Presentation form from an verified Issued JWP
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct JwpPresentedBuilder {
    issuer_protected_header: IssuerProtectedHeader,
    presentation_protected_header: Option<PresentationProtectedHeader>,
    payloads: Payloads,
    issuer_proof: Vec<u8>,
}

impl JwpPresentedBuilder {
    pub fn new(issued_jwp: &JwpIssued) -> Self {
        Self {
            issuer_protected_header: issued_jwp.get_issuer_protected_header().clone(),
            presentation_protected_header: None,
            payloads: issued_jwp.get_payloads().clone(),
            issuer_proof: issued_jwp.get_proof().to_vec(),
        }
    }

    pub fn set_presentation_protected_header(
        &mut self,
        header: PresentationProtectedHeader,
    ) -> &mut Self {
        self.presentation_protected_header = Some(header);
        self
    }

    // Getter for issuer_protected_header
    pub fn get_issuer_protected_header(&self) -> &IssuerProtectedHeader {
        &self.issuer_protected_header
    }

    // Getter for presentation_protected_header
    pub fn get_presentation_protected_header(&self) -> Option<&PresentationProtectedHeader> {
        self.presentation_protected_header.as_ref()
    }

    // Getter for payloads
    pub fn get_payloads(&self) -> &Payloads {
        &self.payloads
    }

    // Getter for issuer_proof
    pub fn issuer_proof(&self) -> &Vec<u8> {
        &self.issuer_proof
    }

    pub fn set_undisclosed(&mut self, claim: &str) -> Result<&mut Self, CustomError> {
        let index = self
            .issuer_protected_header
            .claims()
            .and_then(|c| c.0.iter().position(|x| x == claim))
            .ok_or(CustomError::SelectiveDisclosureError)?;
        self.payloads.set_undisclosed(index);
        Ok(self)
    }

    pub fn build_with_proof(&self, proof: Vec<u8>) -> Result<JwpPresented, CustomError> {
        if let Some(presentation_protected_header) = self.presentation_protected_header.clone() {
            Ok(JwpPresented {
                issuer_protected_header: self.issuer_protected_header.clone(),
                presentation_protected_header,
                payloads: self.payloads.clone(),
                proof,
            })
        } else {
            Err(CustomError::IncompleteJwpBuild(
                crate::errors::IncompleteJwpBuild::NoIssuerHeader,
            ))
        }
    }

    pub fn build(&self, jwk: &Jwk) -> Result<JwpPresented, CustomError> {
        if let Some(presentation_protected_header) = self.presentation_protected_header.clone() {
            let issuer_header_oct = serde_json::to_vec(&self.issuer_protected_header).unwrap();
            let presentation_header_oct =
                serde_json::to_vec(&self.presentation_protected_header).unwrap();

            let proof = Self::generate_proof(
                presentation_protected_header.alg(),
                jwk,
                &self.issuer_proof,
                &issuer_header_oct,
                &presentation_header_oct,
                &self.payloads,
            )?;
            Ok(JwpPresented {
                issuer_protected_header: self.issuer_protected_header.clone(),
                presentation_protected_header,
                payloads: self.payloads.clone(),
                proof,
            })
        } else {
            Err(CustomError::IncompleteJwpBuild(
                crate::errors::IncompleteJwpBuild::NoIssuerHeader,
            ))
        }
    }

    fn generate_proof(
        alg: PresentationProofAlgorithm,
        key: &Jwk,
        issuer_proof: &[u8],
        issuer_header_oct: &[u8],
        presentation_header_oct: &[u8],
        payloads: &Payloads,
    ) -> Result<Vec<u8>, CustomError> {
        let proof = match alg {
            PresentationProofAlgorithm::BLS12381_SHA256_PROOF
            | PresentationProofAlgorithm::BLS12381_SHAKE256_PROOF => {
                BBSplusAlgorithm::generate_presentation_proof(
                    alg,
                    issuer_proof,
                    payloads,
                    key,
                    issuer_header_oct,
                    presentation_header_oct,
                )?
            }
            PresentationProofAlgorithm::SU_ES256 => todo!(),
            PresentationProofAlgorithm::MAC_H256 => todo!(),
            PresentationProofAlgorithm::MAC_H384 => todo!(),
            PresentationProofAlgorithm::MAC_H512 => todo!(),
            PresentationProofAlgorithm::MAC_K25519 => todo!(),
            PresentationProofAlgorithm::MAC_K448 => todo!(),
            PresentationProofAlgorithm::MAC_H256K => todo!(),
        };

        Ok(proof)
    }
}

/// Used for both decoding and verifing a JSON Proof Token representing a JWP in the Presentation form
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct JwpPresentedDecoder {
    issuer_protected_header: IssuerProtectedHeader,
    presentation_protected_header: PresentationProtectedHeader,
    payloads: Payloads,
    proof: Vec<u8>,
}

impl JwpPresentedDecoder {
    /// Decode a JSON Proof Token. The token must represent a Presented JWP, otherwise will return an error.
    pub fn decode(jpt: &str, serialization: SerializationType) -> Result<Self, CustomError> {
        match serialization {
            SerializationType::COMPACT => {
                let (
                    encoded_issuer_protected_header,
                    encoded_presentation_protected_header,
                    encoded_payloads,
                    encoded_proof,
                ) = expect_four!(jpt.splitn(4, '.'));
                let presentation_protected_header: PresentationProtectedHeader = serde_json::from_slice(&base64url_decode(encoded_presentation_protected_header)).map_err(|_| CustomError::SerializationError)?;
                let issuer_protected_header: IssuerProtectedHeader = serde_json::from_slice(&base64url_decode(encoded_issuer_protected_header)).map_err(|_| CustomError::SerializationError)?;
                let payloads = Payloads(
                    encoded_payloads
                        .splitn(issuer_protected_header.claims().unwrap().0.len(), "~")
                        .map(|v| {
                            if v == "" {
                                (serde_json::Value::Null, PayloadType::Undisclosed)
                            } else {
                                (
                                    serde_json::from_slice(&base64url_decode(v)).unwrap(),
                                    PayloadType::Disclosed,
                                )
                            }
                        })
                        .collect(),
                );

                if !match issuer_protected_header.claims() {
                    Some(claims) => claims.0.len() == payloads.0.len(),
                    None => payloads.0.len() == 0,
                } {
                    return Err(CustomError::InvalidIssuedJwp);
                }

                let proof = base64url_decode(encoded_proof);

                Ok(Self {
                    issuer_protected_header,
                    payloads,
                    proof: proof,
                    presentation_protected_header,
                })
            }
            SerializationType::JSON => todo!(),
        }
    }

    /// Verify the decoded JWP
    pub fn verify(&self, key: &Jwk) -> Result<JwpPresented, CustomError> {
        let issuer_header_oct = serde_json::to_vec(&self.issuer_protected_header).unwrap();
        let presentation_header_oct =
            serde_json::to_vec(&self.presentation_protected_header).unwrap();
        Self::verify_proof(
            self.presentation_protected_header.alg(),
            key,
            &self.proof,
            &presentation_header_oct,
            &issuer_header_oct,
            &self.payloads,
        )?;
        Ok(JwpPresented {
            issuer_protected_header: self.issuer_protected_header.clone(),
            presentation_protected_header: self.presentation_protected_header.clone(),
            payloads: self.payloads.clone(),
            proof: self.proof.clone(),
        })
    }

    pub fn get_issuer_header(&self) -> &IssuerProtectedHeader {
        &self.issuer_protected_header
    }

    pub fn get_presentation_header(&self) -> &PresentationProtectedHeader {
        &self.presentation_protected_header
    }

    pub fn get_payloads(&self) -> &Payloads {
        &self.payloads
    }

    fn verify_proof(
        alg: PresentationProofAlgorithm,
        key: &Jwk,
        proof: &[u8],
        presentation_header_oct: &[u8],
        issuer_header_oct: &[u8],
        payloads: &Payloads,
    ) -> Result<(), CustomError> {
        let check = match alg {
            PresentationProofAlgorithm::BLS12381_SHA256_PROOF
            | PresentationProofAlgorithm::BLS12381_SHAKE256_PROOF => {
                BBSplusAlgorithm::verify_presentation_proof(
                    alg,
                    &key,
                    proof,
                    presentation_header_oct,
                    issuer_header_oct,
                    payloads,
                )
            }
            PresentationProofAlgorithm::SU_ES256 => todo!(),
            PresentationProofAlgorithm::MAC_H256 => todo!(),
            PresentationProofAlgorithm::MAC_H384 => todo!(),
            PresentationProofAlgorithm::MAC_H512 => todo!(),
            PresentationProofAlgorithm::MAC_K25519 => todo!(),
            PresentationProofAlgorithm::MAC_K448 => todo!(),
            PresentationProofAlgorithm::MAC_H256K => todo!(),
        };

        check
    }
}

/// Decoded and verified JSON Web Proof in the Presentation form
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct JwpPresented {
    issuer_protected_header: IssuerProtectedHeader,
    presentation_protected_header: PresentationProtectedHeader,
    payloads: Payloads,
    proof: Vec<u8>,
}

impl JwpPresented {
    /// Encode the currently crafted JWP
    pub fn encode(&self, serialization: SerializationType) -> Result<String, CustomError> {
        // let encoded_issuer_header = base64url_encode_serializable(&self.issuer_protected_header);
        // let encoded_presentation_header = base64url_encode_serializable(&self.presentation_protected_header);

        let issuer_header_oct = serde_json::to_vec(&self.issuer_protected_header)
        .map_err(|_| CustomError::SerializationError)?;

        let presentation_header_oct =
            serde_json::to_vec(&self.presentation_protected_header)
            .map_err(|_| CustomError::SerializationError)?;

        let jwp = Self::serialize(
            serialization,
            &presentation_header_oct,
            &issuer_header_oct,
            &self.payloads,
            &self.proof,
        );

        Ok(jwp)
    }

    pub fn get_issuer_protected_header(&self) -> &IssuerProtectedHeader {
        &self.issuer_protected_header
    }

    pub fn get_presentation_protected_header(&self) -> &PresentationProtectedHeader {
        &self.presentation_protected_header
    }

    pub fn get_claims(&self) -> Option<&Claims> {
        self.issuer_protected_header.claims()
    }

    pub fn get_payloads(&self) -> &Payloads {
        &self.payloads
    }

    pub fn get_proof(&self) -> &[u8] {
        &self.proof
    }

    fn serialize(
        serialization: SerializationType,
        presentation_header_oct: &[u8],
        issuer_header_oct: &[u8],
        payloads: &Payloads,
        proof: &[u8],
    ) -> String {
        let encoded_issuer_header = base64url_encode(issuer_header_oct);
        let encoded_presentation_header = base64url_encode(presentation_header_oct);
        let encoded_proof = base64url_encode(proof);

        let jwp = match serialization {
            SerializationType::COMPACT => {
                let encoded_payloads = payloads
                    .0
                    .iter()
                    .map(|p| {
                        if p.1 == PayloadType::Undisclosed {
                            "".to_string()
                        } else {
                            base64url_encode_serializable(&p.0)
                        }
                    })
                    .collect::<Vec<String>>()
                    .join("~");
                format!(
                    "{}.{}.{}.{}",
                    encoded_issuer_header,
                    encoded_presentation_header,
                    encoded_payloads,
                    encoded_proof
                )
            }
            SerializationType::JSON => todo!(),
        };

        jwp
    }
}
