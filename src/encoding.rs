// Copyright 2025 Fondazione LINKS

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at

//     http://www.apache.org/licenses/LICENSE-2.0

// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use data_encoding::BASE64URL_NOPAD;
use serde::Serialize;

pub enum SerializationType {
    COMPACT,
    JSON,
    CBOR,
}

pub fn base64url_encode<T: AsRef<[u8]>>(bytes: T) -> String {
    BASE64URL_NOPAD.encode(bytes.as_ref())
}

pub fn base64url_decode<T: AsRef<[u8]>>(bytes: T) -> Vec<u8> {
    BASE64URL_NOPAD.decode(bytes.as_ref()).unwrap()
}

// Encodes a struct in base64url
pub fn base64url_encode_serializable<T: Serialize>(value: T) -> String {
    let bytes = serde_json::to_vec(&value).unwrap();
    base64url_encode(bytes)
}

pub struct EncondingKey {
    //TODO: family attribute implement something like this
    //             ProofAlgorithm::EdDSA => AlgorithmFamily::Ed,
    //             ProofAlgorithm::BBS_X (or BBS_BLS12381_SHA256, BBS_BLS12381_SHAKE256) => AlgorithmFamily::Bls12381
}

//TODO: implement From<Jwk> trait that transform a Jwk into and EncodingKey
//es. if crv

pub struct DecondingKey {}
