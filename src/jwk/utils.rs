use crate::jpa::algs::ProofAlgorithm;

use super::alg_parameters::Algorithm;
use super::curves::EllipticCurveTypes;
use super::key::Jwk;

pub fn check_alg_curve_compatibility(alg: Algorithm, crv: EllipticCurveTypes) -> bool {
    match (alg, crv) {
        // (Algorithm::Signature(SignatureAlgorithm::ES256), EllipticCurveTypes::P256) => true, EXAMPLE
        (Algorithm::Proof(ProofAlgorithm::BLS12381_SHA256), EllipticCurveTypes::Bls12_381) => true,
        (Algorithm::Proof(ProofAlgorithm::BLS12381_SHAKE256), EllipticCurveTypes::Bls12_381) => true,
        _ => false
      }
}