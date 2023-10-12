use serde::{Deserialize, Serialize, ser::SerializeMap};

use crate::{jpt::{payloads::{Payloads, PayloadType}, claims::Claims}, encoding::{base64url_encode, base64url_encode_serializable, SerializationType}};

use super::header::IssuerProtectedHeader;


#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct JwpIssuedForm {
    issuer_protected_header: IssuerProtectedHeader,
    payloads: Payloads,
    proof: Option<Vec<u8>>
}

impl JwpIssuedForm {

    pub fn new(issuer_protected_header: IssuerProtectedHeader, payloads: Payloads) -> Self{
        Self { issuer_protected_header, payloads, proof: None }
    }

    //TODO: here should be pass as parameter the JWK used to generate the proof and inside we call the generate_proof method
    pub fn encode(&self, serialization: SerializationType) -> String{

        let jwp = match serialization {
            SerializationType::COMPACT => {
                let encoded_issuer_header = base64url_encode_serializable(&self.issuer_protected_header);
                let encoded_payloads = self.payloads.0.iter().map(|p| {
                    if p.1 == PayloadType::Undisclosed {
                        "".to_string()
                    } else {
                        p.0.clone()
                    }
                })
                .collect::<Vec<String>>()
                .join("~");

                format!("{}.{}.{}", encoded_issuer_header, encoded_payloads, "")
                
            },
            SerializationType::JSON => todo!(),
        };
        
        jwp
    }

    pub fn generate_proof() {
        todo!()
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
}