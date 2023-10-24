use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{encoding::base64url_encode_serializable, errors::CustomError};

///TODO: Not clear what to do with this information 
/// (https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-proof-token#name-payloads)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum PayloadType{
    Disclosed,
    Undisclosed,
    ProofMethods
}


#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Payloads (pub Vec<(String, PayloadType)>);

impl Payloads {
    pub fn new_from_values(values: Vec<Value>) -> Self {
        // TODO: change this, should not be base64url encoded here, 
        // because the proof is computed over this but should be 
        // computed over octet strings 
        Self(values.iter().map(|v| (base64url_encode_serializable(v), PayloadType::Disclosed)).collect())
    }

    pub fn get_undisclosed_indexes(&self) -> Vec<usize> {
        let mut undisclosed_indexes = Vec::new();

        for (index, (_, payload_type)) in self.0.iter().enumerate() {
            if let PayloadType::Undisclosed = payload_type {
                undisclosed_indexes.push(index);
            }
        }

        undisclosed_indexes
    }

    pub fn get_disclosed_indexes(&self) -> Vec<usize> {
        let mut disclosed_indexes = Vec::new();

        for (index, (_, payload_type)) in self.0.iter().enumerate() {
            if let PayloadType::Disclosed = payload_type {
                disclosed_indexes.push(index);
            }
        }

        disclosed_indexes
    }


    pub fn set_disclosed(&mut self, index: usize, disclosed: bool) -> Result<(), CustomError>{
        if let Some(p) = self.0.get_mut(index) {
            // Get the reference to the tuple at the specified index
    
            // Preserve the String value while changing the PayloadType
            let payload_value = p.0.clone();
            match disclosed {
                true => *p = (payload_value, PayloadType::Disclosed),
                false => *p = (payload_value, PayloadType::Undisclosed)
            };
            Ok(())
        } else {
            // Handle the case where the index is out of bounds
            Err(CustomError::IndexOutOfBounds)
        }
    }
}