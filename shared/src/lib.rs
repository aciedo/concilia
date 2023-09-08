mod ballot;
mod vote;
mod error;

pub use ballot::*;
pub use vote::*;
pub use error::*;

pub trait StringConversion: Sized {
    fn as_string(&self) -> String;
    fn from_string(s: String) -> Option<Self>;
}
