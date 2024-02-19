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
        Base64UrlDecodedSerializable, SerializationType,
    },
    errors::CustomError,
    jpa::{algs::ProofAlgorithm, bbs_plus::BBSplusAlgorithm},
    jpt::{
        claims::{Claims, JptClaims},
        payloads::{PayloadType, Payloads},
    },
    jwk::key::Jwk,
};

use super::header::IssuerProtectedHeader;

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

/// Used to build a new JSON Web Proof in the Issuer form
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct JwpIssuedBuilder {
    issuer_protected_header: Option<IssuerProtectedHeader>,
    payloads: Option<Payloads>,
}

impl JwpIssuedBuilder {
    pub fn new() -> Self {
        Self {
            issuer_protected_header: None,
            payloads: None,
        }
    }

    pub fn issuer_protected_header(&mut self, header: IssuerProtectedHeader) -> &mut Self {
        self.issuer_protected_header = Some(header);
        self
    }

    pub fn jpt_claims(&mut self, jpt_claims: JptClaims) -> &mut Self {
        let (claims, payloads) = jpt_claims.get_claims_and_payloads();
        //Set claims
        self.issuer_protected_header
            .as_mut()
            .and_then(|h| Some(h.set_claims(Some(claims))));
        //Set payloads
        self.payloads = Some(payloads);
        self
    }

    pub fn build(&self, jwk: &Jwk) -> Result<JwpIssued, CustomError> {
        if let Some(issuer_protected_header) = self.issuer_protected_header.clone() {
            if let Some(payloads) = self.payloads.clone() {
                let issuer_header_oct = serde_json::to_vec(&self.issuer_protected_header).unwrap();
                let proof = Self::generate_proof(
                    issuer_protected_header.alg(),
                    &jwk,
                    &issuer_header_oct,
                    &payloads,
                )?;

                Ok(JwpIssued {
                    issuer_protected_header,
                    payloads,
                    proof,
                })
            } else {
                Err(CustomError::IncompleteJwpBuild(
                    crate::errors::IncompleteJwpBuild::NoClaimsAndPayloads,
                ))
            }
        } else {
            Err(CustomError::IncompleteJwpBuild(
                crate::errors::IncompleteJwpBuild::NoIssuerHeader,
            ))
        }
    }

    fn generate_proof(
        alg: ProofAlgorithm,
        key: &Jwk,
        issuer_header_oct: &[u8],
        payloads: &Payloads,
    ) -> Result<Vec<u8>, CustomError> {
        let proof = match alg {
            ProofAlgorithm::BLS12381_SHA256 | ProofAlgorithm::BLS12381_SHAKE256 => {
                BBSplusAlgorithm::generate_issuer_proof(alg, payloads, key, issuer_header_oct)?
            }
            ProofAlgorithm::SU_ES256 => todo!(),
            ProofAlgorithm::MAC_H256 => todo!(),
            ProofAlgorithm::MAC_H384 => todo!(),
            ProofAlgorithm::MAC_H512 => todo!(),
            ProofAlgorithm::MAC_K25519 => todo!(),
            ProofAlgorithm::MAC_K448 => todo!(),
            ProofAlgorithm::MAC_H256K => todo!(),
        };

        Ok(proof)
    }
}

/// Used for both decoding and verifing a JSON Proof Token representing a JWP in the Issuer form
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct JwpIssuedDecoder {
    issuer_protected_header: IssuerProtectedHeader,
    payloads: Payloads,
    proof: Vec<u8>,
}

impl JwpIssuedDecoder {
    /// Decode a JSON Proof Token. The token must represent an Issued JWP, otherwise will return an error.
    pub fn decode(jpt: &str, serialization: SerializationType) -> Result<Self, CustomError> {
        match serialization {
            SerializationType::COMPACT => {
                let (encoded_issuer_protected_header, encoded_payloads, encoded_proof) =
                    expect_three!(jpt.splitn(3, '.'));
                //TODO: this needs to be checked because doesn't return an error if the value is not deserializable into an IssuerProtectedHeader struct
                let issuer_protected_header: IssuerProtectedHeader =
                    Base64UrlDecodedSerializable::from_serializable_values(
                        encoded_issuer_protected_header,
                    )
                    .deserialize::<IssuerProtectedHeader>();

                //TODO: this could not have much sense for now (maybe useful to handle blind signatures?)
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
                })
            }
            SerializationType::JSON => todo!(),
        }
    }

    /// Verify the decoded JWP
    pub fn verify(&self, key: &Jwk) -> Result<JwpIssued, CustomError> {
        let issuer_header_oct = serde_json::to_vec(&self.issuer_protected_header).unwrap();

        Self::verify_proof(
            self.issuer_protected_header.alg(),
            key,
            &self.proof,
            &issuer_header_oct,
            &self.payloads,
        )?;

        Ok(JwpIssued {
            issuer_protected_header: self.issuer_protected_header.clone(),
            payloads: self.payloads.clone(),
            proof: self.proof.clone(),
        })
    }

    pub fn get_header(&self) -> &IssuerProtectedHeader {
        &self.issuer_protected_header
    }

    pub fn get_payloads(&self) -> &Payloads {
        &self.payloads
    }

    fn verify_proof(
        alg: ProofAlgorithm,
        key: &Jwk,
        proof: &[u8],
        issuer_header_oct: &[u8],
        payloads: &Payloads,
    ) -> Result<(), CustomError> {
        let check = match alg {
            ProofAlgorithm::BLS12381_SHA256 | ProofAlgorithm::BLS12381_SHAKE256 => {
                BBSplusAlgorithm::verify_issuer_proof(alg, &key, proof, issuer_header_oct, payloads)
            }
            ProofAlgorithm::SU_ES256 => todo!(),
            ProofAlgorithm::MAC_H256 => todo!(),
            ProofAlgorithm::MAC_H384 => todo!(),
            ProofAlgorithm::MAC_H512 => todo!(),
            ProofAlgorithm::MAC_K25519 => todo!(),
            ProofAlgorithm::MAC_K448 => todo!(),
            ProofAlgorithm::MAC_H256K => todo!(),
        };

        check
    }
}

/// Decoded and verified JSON Web Proof in the Issuer form
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct JwpIssued {
    issuer_protected_header: IssuerProtectedHeader,
    payloads: Payloads,
    proof: Vec<u8>,
}

impl JwpIssued {
    /// Encode the currently crafted JWP
    pub fn encode(&self, serialization: SerializationType) -> Result<String, CustomError> {
        // let encoded_issuer_header = base64url_encode_serializable(&self.issuer_protected_header);

        let issuer_header_oct = serde_json::to_vec(&self.issuer_protected_header).unwrap();

        let jwp = Self::serialize(
            serialization,
            &issuer_header_oct,
            &self.payloads,
            &self.proof,
        );

        Ok(jwp)
    }

    pub fn get_issuer_protected_header(&self) -> &IssuerProtectedHeader {
        &self.issuer_protected_header
    }

    pub fn get_claims(&self) -> Option<&Claims> {
        self.issuer_protected_header.claims()
    }

    pub fn set_claims(&mut self, claims: Claims) {
        self.issuer_protected_header.set_claims(Some(claims));
    }

    pub fn get_payloads(&self) -> &Payloads {
        &self.payloads
    }

    pub fn set_payloads(&mut self, payloads: Payloads) {
        self.payloads = payloads;
    }

    pub fn get_proof(&self) -> &[u8] {
        self.proof.as_ref()
    }

    pub fn set_proof(&mut self, proof: &[u8]) {
        self.proof = proof.to_vec();
    }

    fn serialize(
        serialization: SerializationType,
        issuer_header_oct: &[u8],
        payloads: &Payloads,
        proof: &[u8],
    ) -> String {
        let encoded_issuer_header = base64url_encode(issuer_header_oct);
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
                    "{}.{}.{}",
                    encoded_issuer_header, encoded_payloads, encoded_proof
                )
            }
            SerializationType::JSON => todo!(),
        };

        jwp
    }
}
