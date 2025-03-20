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

use super::alg_parameters::Algorithm;
use super::curves::EllipticCurveTypes;
use crate::jpa::algs::{PresentationProofAlgorithm, ProofAlgorithm};

pub fn check_alg_curve_compatibility(alg: Algorithm, crv: EllipticCurveTypes) -> bool {
    match (alg, crv) {
        // (Algorithm::Signature(SignatureAlgorithm::ES256), EllipticCurveTypes::P256) => true, EXAMPLE
        (Algorithm::Proof(ProofAlgorithm::BBS), EllipticCurveTypes::BLS12381G2) => true,
        (Algorithm::Proof(ProofAlgorithm::BBS_SHAKE256), EllipticCurveTypes::BLS12381G2) => {
            true
        }
        _ => false,
    }
}

pub fn check_presentation_alg_curve_compatibility(
    alg: PresentationProofAlgorithm,
    crv: EllipticCurveTypes,
) -> bool {
    match (alg, crv) {
        // (Algorithm::Signature(SignatureAlgorithm::ES256), EllipticCurveTypes::P256) => true, EXAMPLE
        (PresentationProofAlgorithm::BBS, EllipticCurveTypes::BLS12381G2) => true,
        (PresentationProofAlgorithm::BBS_SHAKE256, EllipticCurveTypes::BLS12381G2) => {
            true
        }
        _ => false,
    }
}
