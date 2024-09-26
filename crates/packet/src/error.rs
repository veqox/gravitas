use std::{error::Error, fmt::Display};

#[derive(Debug)]
pub enum DNSError {
    InvalidType(u16),
    InvalidQType(u16),
    InvalidClass(u16),
    InvalidQClass(u16),
}

impl Display for DNSError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Error: {:?}", self)
    }
}

impl Error for DNSError {}
