use thiserror::Error;

#[derive(Error, Debug)]
pub enum CustomError {
    /// Error indicating that only objects can be flattened.
    #[error("Flattening can only be performed on objects")]
    InvalidInputObjectType,

    /// Error indicating that flattening the object will result in a key collision with the given key.
    #[error("Flattening the object will result in key collision: '{0}'")]
    KeyCollision(String),
}

pub struct MyError(pub String);