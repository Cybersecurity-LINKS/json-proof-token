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



use serde::{Deserialize, Serialize};
use serde_json::Value;
use crate::errors::CustomError;

///TODO: Not clear what to do with this information 
/// (https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-proof-token#name-payloads)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum PayloadType{
    Disclosed,
    Undisclosed,
    ProofMethods
}


#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Payloads (pub Vec<(Value, PayloadType)>);

impl Payloads {
    pub fn new_from_values(values: Vec<Value>) -> Self {
        let mut payloads = Vec::new();
        for value in values {
            payloads.push((value, PayloadType::Disclosed));
        }
        Payloads(payloads)
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


    pub fn get_undisclosed_payloads(&self) -> Vec<Value> {
        let undisclosed_indexes = self.get_undisclosed_indexes();

        let undisclosed_payloads: Vec<Value> = self.0
            .iter()
            .enumerate()
            .filter(|(index, _)| undisclosed_indexes.contains(index))
            .map(|(_, payload)| payload.0.clone())
            .collect();

        undisclosed_payloads
    }

    pub fn get_disclosed_payloads(&self) -> Vec<Value> {
        let disclosed_indexes = self.get_disclosed_indexes();

        let disclosed_payloads: Vec<Value> = self.0
            .iter()
            .enumerate()
            .filter(|(index, _)| disclosed_indexes.contains(index))
            .map(|(_, payload)| payload.0.clone())
            .collect();

        disclosed_payloads
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