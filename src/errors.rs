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
}