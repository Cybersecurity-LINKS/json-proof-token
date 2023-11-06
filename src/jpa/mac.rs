use std::mem::ManuallyDrop;

use serde::{Deserialize, Serialize};

pub trait MACAlgorithm {
    //TODO: MAC functions    
}
#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct MACImplementation;

impl MACAlgorithm for MACImplementation{}