use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};


pub(crate) fn base64url_encode<T: AsRef<[u8]>>(bytes: T) -> String {
    BASE64URL_NOPAD.encode(bytes.as_ref())
}


pub(crate) fn base64url_decode<T: AsRef<[u8]>>(bytes: T) -> Vec<u8> {
    BASE64URL_NOPAD.decode(bytes.as_ref()).unwrap()
}


// Encodes a struct in base64url
pub(crate) fn base64url_encode_serializable<T: Serialize>(value: T) -> String{
    let bytes = serde_json::to_vec(&value).unwrap();
    base64url_encode(bytes)
}



/// Decodes a base64url-encoded string and deserializes it into user-defined structs.
///
/// This function takes a base64-encoded string as input and performs the following steps:
/// 1. Decodes the input from base64 encoding.
/// 2. Deserializes the resulting binary data into a user-provided struct.
pub(crate) struct Base64UrlDecodedSerializable {
    base64url_decoded: Vec<u8>
}

impl Base64UrlDecodedSerializable {
    pub fn from_serializable_values(encoded_serializable_value: impl AsRef<[u8]>) -> Self {
        Self { base64url_decoded: base64url_decode(encoded_serializable_value) }
    }

    pub fn deserialize<'a, T: Deserialize<'a>>(&'a self) -> T {
        serde_json::from_slice(&self.base64url_decoded).unwrap()
    }
}