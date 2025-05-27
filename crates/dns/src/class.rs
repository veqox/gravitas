#[derive(Debug, Clone, PartialEq, Eq)]
#[repr(u16)]
pub enum Class {
    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4)
    IN,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4)
    CH,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4)
    HS,

    /// [RFC 2136](https://www.rfc-editor.org/rfc/rfc2136)
    NONE,

    /// [RFC 1035](https://www.rfc-editor.org/rfc/rfc1035#section-3.2.4)
    ANY,

    /// [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891#section-6.1.2)
    OPT(u16),
}

impl From<u16> for Class {
    fn from(value: u16) -> Self {
        match value {
            1 => Self::IN,
            3 => Self::CH,
            4 => Self::HS,
            254 => Self::NONE,
            255 => Self::ANY,
            x => Self::OPT(x.max(512)),
        }
    }
}

impl From<Class> for u16 {
    fn from(val: Class) -> Self {
        match val {
            Class::IN => 1,
            Class::CH => 3,
            Class::HS => 4,
            Class::NONE => 254,
            Class::ANY => 255,
            Class::OPT(x) => x,
        }
    }
}
