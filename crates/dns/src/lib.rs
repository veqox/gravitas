mod class;
mod header;
mod packet;
pub mod proto;
mod question;
mod resource_record;
mod r#type;

pub use crate::class::Class;
pub use crate::header::Header;
pub use crate::header::OpCode;
pub use crate::header::RCode;
pub use crate::packet::Packet;
pub use crate::question::Question;
pub use crate::resource_record::Record;
pub use crate::resource_record::ResourceRecord;
pub use crate::r#type::Type;
