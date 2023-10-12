use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
#[allow(non_camel_case_types)]
pub enum ProofAlgorithm {
  // BBS_X, //TODO: probably create two algorithms (BLS12381_SHA256 and BLS12381_SHAKE256)
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



#[derive(Debug, Eq, PartialEq, Copy, Clone, Serialize, Deserialize)]
pub(crate) enum AlgorithmFamily {
    Hmac,
    Rsa,
    Ec,
    Ed,
}

