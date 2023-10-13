use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[allow(non_camel_case_types)]
pub enum ProofAlgorithm {
  // #[serde(rename = "BBS-X")]
  // BBS_X, 

  ///TODO: we need two algorithms (BLS12381_SHA256 and BLS12381_SHAKE256) instead of 
  /// just BBS-X to distinguish between the two ciphersuites
  /// We should also distinguish between the BBS algorithm standard and the one extended
  #[serde(rename = "BBS-BLS12381-SHA256")]
  BLS12381_SHA256,
  #[serde(rename = "BBS-BLS12381-SHAKE256")]
  BLS12381_SHAKE256,

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
  MAC_H256K
}


// pub trait ProofGenerator {
//   fn generate_issuer_proof(&self) -> Option<Vec<u8>>;
//   fn generate_presentaiton_proof(&self) -> Option<Vec<u8>>;
// }
