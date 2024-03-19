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

use crate::errors::CustomError;
use serde::{Deserialize, Serialize};
use serde_json::Value;

///TODO: Not clear what to do with this information
/// (https://datatracker.ietf.org/doc/html/draft-ietf-jose-json-proof-token#name-payloads)
#[derive(Clone, Copy, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub enum PayloadType {
    Disclosed,
    Undisclosed,
    ProofMethods,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Payloads(pub Vec<(Value, PayloadType)>);

impl Payloads {

    pub fn to_bytes(&self) -> Result<Vec<Vec<u8>>, CustomError> {
        let p: Result<Vec<Vec<u8>>, CustomError> = self.0.iter().map(|v| {
            match serde_json::to_vec(&v.0) {
                Ok(vec) => Ok(vec),
                Err(_) => Err(CustomError::SerializationError),
            }
        }).collect();
        p
    }
    pub fn new_from_values(values: Vec<Value>) -> Self {
        let mut payloads = Vec::new();
        for value in values {
            payloads.push((value, PayloadType::Disclosed));
        }
        Payloads(payloads)
    }

    pub fn get_values(&self) -> Vec<Value> {
        self.0.clone().into_iter().map(|v| v.0).collect()
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

        let undisclosed_payloads: Vec<Value> = self
            .0
            .iter()
            .enumerate()
            .filter(|(index, _)| undisclosed_indexes.contains(index))
            .map(|(_, payload)| payload.0.clone())
            .collect();

        undisclosed_payloads
    }

    pub fn get_disclosed_payloads(&self) -> Payloads {
        let disclosed_indexes = self.get_disclosed_indexes();

        let disclosed_payloads: Vec<(Value, PayloadType)> = self
            .0
            .iter()
            .enumerate()
            .filter(|(index, _)| disclosed_indexes.contains(index))
            .map(|(_, payload)| payload.clone())
            .collect();

        Payloads(disclosed_payloads)
    }

    pub fn set_undisclosed(&mut self, index: usize) {
        self.0.iter_mut().enumerate().for_each(|(i, v)| {
            if index == i {
                v.1 = PayloadType::Undisclosed;
            }
        });
    }

    pub fn replace_payload_at_index(
        &mut self,
        index: usize,
        value: Value,
    ) -> Result<Value, CustomError> {
        let dest = self.0.get_mut(index).ok_or(CustomError::IndexOutOfBounds)?;
        let old = std::mem::replace(dest, (value, PayloadType::Disclosed));
        Ok(old.0)
    }
}
