use serde::{Deserialize, Serialize};

pub trait SUAlgorithm{
    //TODO: implement SU functions
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Deserialize, Serialize)]
pub struct SUImplementation;

impl SUAlgorithm for SUImplementation{}