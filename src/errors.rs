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

use thiserror::Error;

#[derive(Error, Debug)]
pub enum CustomError {
    #[error("Error during generation of a proof")]
    ProofGenerationError(String),

    #[error("Error during verification of a proof")]
    ProofVerificationError(String),

    #[error("Error during creation of a JWK")]
    JwkGenerationError(String),

    #[error("Issued Jwp NOT valid")]
    InvalidIssuedJwp,

    #[error("Presented Jwp NOT valid")]
    InvalidPresentedJwp,

    #[error("Issued Proof verification failed!")]
    InvalidIssuedProof,

    #[error("Presented Proof verification failed!")]
    InvalidPresentedProof,

    #[error("Index out of bounds!")]
    IndexOutOfBounds,

    #[error("Incomplete Jwp build")]
    IncompleteJwpBuild(IncompleteJwpBuild),

    #[error("Error during JSON flattening process")]
    FlatteningError,

    #[error("Error during selective disclosure of an attribute")]
    SelectiveDisclosureError,
}

#[derive(Error, Debug)]
pub enum IncompleteJwpBuild {
    #[error("Issuer Header Not set!")]
    NoIssuerHeader,

    #[error("Presentation Header Not set!")]
    NoPresentationHeader,

    #[error("Claims and Payloads Not set!")]
    NoClaimsAndPayloads,

    #[error("JWK Not set! Cannot generate a JWP!")]
    NoJwk,
}
