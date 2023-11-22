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



use std::mem::ManuallyDrop;

use serde::{Deserialize, Serialize};


#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct MACImplementation<M: MACAlgorithm> (M);

impl <M: MACAlgorithm>MACImplementation<M> {
    pub fn new(implementation: M) -> Self {
        Self(implementation)
    }
}

impl Default for MACImplementation<DefaultMACImplementation> {
    fn default() -> Self {
        Self(DefaultMACImplementation)
    }
}


pub trait MACAlgorithm {
    //TODO: MAC functions    
}
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct DefaultMACImplementation;

impl MACAlgorithm for DefaultMACImplementation{}