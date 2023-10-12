use serde::{Deserialize, Serialize};

use crate::jpt::{payloads::Payloads, claims::Claims};

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

    pub fn encode() {
        todo!()
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