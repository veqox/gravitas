pub mod header;
pub mod packet;
pub mod parser;
pub mod question;
pub mod resource_record;
pub mod serializer;

pub use crate::parser::Parser;
pub use crate::serializer::Serializer;
