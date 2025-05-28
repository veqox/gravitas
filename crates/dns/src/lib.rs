mod class;
mod domain_name;
mod header;
mod packet;
pub mod proto;
mod question;
mod rr;
mod r#type;

pub use crate::class::Class;
pub use crate::domain_name::DomainName;
pub use crate::header::Header;
pub use crate::header::OpCode;
pub use crate::header::RCode;
pub use crate::packet::Packet;
pub use crate::question::Question;
pub use crate::rr::ResourceRecord;
pub use crate::r#type::Type;
