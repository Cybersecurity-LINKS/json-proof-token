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

use std::{fmt, str::FromStr};

use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[allow(non_camel_case_types)]
pub enum ProofAlgorithm {
    ///BBS_SHAKE256 temporary name not included in the JPA draft 06
    /// We should also distinguish between the BBS algorithm standard and the one extended
    #[serde(rename = "BBS")]
    BBS,
    #[serde(rename = "BBS-SHAKE256")]
    BBS_SHAKE256,
    #[serde(rename = "SU-ES256")]
    SU_ES256,
    #[serde(rename = "MAC-H256")]
    MAC_H256,
    #[serde(rename = "MAC-H384")]
    MAC_H384,
    #[serde(rename = "MAC-H512")]
    MAC_H512,
    #[serde(rename = "MAC-K25519")]
    MAC_K25519,
    #[serde(rename = "MAC-K448")]
    MAC_K448,
    #[serde(rename = "MAC-H256K")]
    MAC_H256K,
}

impl Into<PresentationProofAlgorithm> for ProofAlgorithm {
    fn into(self) -> PresentationProofAlgorithm {
        match self {
            ProofAlgorithm::BBS => PresentationProofAlgorithm::BBS_PROOF,
            ProofAlgorithm::BBS_SHAKE256 => {
                PresentationProofAlgorithm::BBS_SHAKE256_PROOF
            }
            ProofAlgorithm::SU_ES256 => PresentationProofAlgorithm::SU_ES256,
            ProofAlgorithm::MAC_H256 => PresentationProofAlgorithm::MAC_H256,
            ProofAlgorithm::MAC_H384 => PresentationProofAlgorithm::MAC_H384,
            ProofAlgorithm::MAC_H512 => PresentationProofAlgorithm::MAC_H512,
            ProofAlgorithm::MAC_K25519 => PresentationProofAlgorithm::MAC_K25519,
            ProofAlgorithm::MAC_K448 => PresentationProofAlgorithm::MAC_K448,
            ProofAlgorithm::MAC_H256K => PresentationProofAlgorithm::MAC_H256K,
        }
    }
}

impl fmt::Display for ProofAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant_str = match self {
            ProofAlgorithm::BBS => "BBS",
            ProofAlgorithm::BBS_SHAKE256 => "BBS-SHAKE256",
            ProofAlgorithm::SU_ES256 => "SU-ES256",
            ProofAlgorithm::MAC_H256 => "MAC-H256",
            ProofAlgorithm::MAC_H384 => "MAC-H384",
            ProofAlgorithm::MAC_H512 => "MAC-H512",
            ProofAlgorithm::MAC_K25519 => "MAC-K25519",
            ProofAlgorithm::MAC_K448 => "MAC-K448",
            ProofAlgorithm::MAC_H256K => "MAC-H256K",
        };
        write!(f, "{}", variant_str)
    }
}

impl FromStr for ProofAlgorithm {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "BBS" => Ok(ProofAlgorithm::BBS),
            "BBS-SHAKE256" => Ok(ProofAlgorithm::BBS_SHAKE256),
            "SU-ES256" => Ok(ProofAlgorithm::SU_ES256),
            "MAC-H256" => Ok(ProofAlgorithm::MAC_H256),
            "MAC-H384" => Ok(ProofAlgorithm::MAC_H384),
            "MAC-H512" => Ok(ProofAlgorithm::MAC_H512),
            "MAC-K25519" => Ok(ProofAlgorithm::MAC_K25519),
            "MAC-K448" => Ok(ProofAlgorithm::MAC_K448),
            "MAC-H256K" => Ok(ProofAlgorithm::MAC_H256K),
            _ => Err("Invalid proof algorithm"),
        }
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[allow(non_camel_case_types)]
pub enum PresentationProofAlgorithm {
    ///BBS_PROOF temporary name not included in the JPA draft 06
    #[serde(rename = "BBS-PROOF")]
    BBS_PROOF,
    #[serde(rename = "BBS-SHAKE256-PROOF")]
    BBS_SHAKE256_PROOF,

    #[serde(rename = "SU-ES256")]
    SU_ES256,
    #[serde(rename = "MAC-H256")]
    MAC_H256,
    #[serde(rename = "MAC-H384")]
    MAC_H384,
    #[serde(rename = "MAC-H512")]
    MAC_H512,
    #[serde(rename = "MAC-K25519")]
    MAC_K25519,
    #[serde(rename = "MAC-K448")]
    MAC_K448,
    #[serde(rename = "MAC-H256K")]
    MAC_H256K,
}

impl fmt::Display for PresentationProofAlgorithm {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let variant_str = match self {
            PresentationProofAlgorithm::BBS_PROOF => "BBS-PROOF",
            PresentationProofAlgorithm::BBS_SHAKE256_PROOF => "BBS-SHAKE256-PROOF",
            PresentationProofAlgorithm::SU_ES256 => "SU-ES256",
            PresentationProofAlgorithm::MAC_H256 => "MAC-H256",
            PresentationProofAlgorithm::MAC_H384 => "MAC-H384",
            PresentationProofAlgorithm::MAC_H512 => "MAC-H512",
            PresentationProofAlgorithm::MAC_K25519 => "MAC-K25519",
            PresentationProofAlgorithm::MAC_K448 => "MAC-K448",
            PresentationProofAlgorithm::MAC_H256K => "MAC-H256K",
        };
        write!(f, "{}", variant_str)
    }
}

impl FromStr for PresentationProofAlgorithm {
    type Err = &'static str;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "BBS-PROOF" => Ok(PresentationProofAlgorithm::BBS_PROOF),
            "BBS-SHAKE256-PROOF" => {
                Ok(PresentationProofAlgorithm::BBS_SHAKE256_PROOF)
            }
            "SU-ES256" => Ok(PresentationProofAlgorithm::SU_ES256),
            "MAC-H256" => Ok(PresentationProofAlgorithm::MAC_H256),
            "MAC-H384" => Ok(PresentationProofAlgorithm::MAC_H384),
            "MAC-H512" => Ok(PresentationProofAlgorithm::MAC_H512),
            "MAC-K25519" => Ok(PresentationProofAlgorithm::MAC_K25519),
            "MAC-K448" => Ok(PresentationProofAlgorithm::MAC_K448),
            "MAC-H256K" => Ok(PresentationProofAlgorithm::MAC_H256K),
            _ => Err("Invalid proof algorithm"),
        }
    }
}
