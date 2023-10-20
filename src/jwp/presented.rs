use serde::{Deserialize, Serialize};

use crate::jpt::{payloads::Payloads, claims::Claims};

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
    proof: Option<Vec<u8>>
}

impl JwpPresented {

    pub fn new(issuer_protected_header: IssuerProtectedHeader, presentation_protected_header: PresentationProtectedHeader, payloads: Payloads) -> Self {
        Self { issuer_protected_header, presentation_protected_header, payloads, proof: None }
    }

    pub fn encode() {
        todo!()
    }
    pub fn decode() {
        todo!()
    }

    pub fn generate_proof() {
        todo!()
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
}