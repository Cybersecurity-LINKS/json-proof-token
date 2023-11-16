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



use crate::jpa::algs::ProofAlgorithm;
use super::alg_parameters::Algorithm;
use super::curves::EllipticCurveTypes;

pub fn check_alg_curve_compatibility(alg: Algorithm, crv: EllipticCurveTypes) -> bool {
    match (alg, crv) {
        // (Algorithm::Signature(SignatureAlgorithm::ES256), EllipticCurveTypes::P256) => true, EXAMPLE
        (Algorithm::Proof(ProofAlgorithm::BLS12381_SHA256), EllipticCurveTypes::Bls12381G2) => true,
        (Algorithm::Proof(ProofAlgorithm::BLS12381_SHAKE256), EllipticCurveTypes::Bls12381G2) => true,
        (Algorithm::Proof(ProofAlgorithm::BLS12381_SHA256_PROOF), EllipticCurveTypes::Bls12381G2) => true,
        (Algorithm::Proof(ProofAlgorithm::BLS12381_SHAKE256_PROOF), EllipticCurveTypes::Bls12381G2) => true,
        _ => false
      }
}