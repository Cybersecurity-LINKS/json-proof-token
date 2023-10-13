use thiserror::Error;

#[derive(Error, Debug)]
pub enum CustomError {
    #[error("Error during generation of a proof")]
    ProofGenerationError(String),

    #[error("Error during verification of a proof")]
    ProofVerificationError(String),

    #[error("Error during creation of a JWK")]
    JwkGenerationError(String)
}