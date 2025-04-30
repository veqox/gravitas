use crate::{class::Class, r#type::Type};

/// DNS resource record field layout as per [RFC 1035 Section 4.1.3](https://www.rfc-editor.org/rfc/rfc1035#section-4.1.3)
///
/// ```text
///   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                               |
/// /                                               /
/// /                      NAME                     /
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      TYPE                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                     CLASS                     |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                      TTL                      |
/// |                                               |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                   RDLENGTH                    |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--|
/// /                     RDATA                     /
/// /                                               /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug)]
pub struct ResourceRecord<'a> {
    pub name: Vec<&'a [u8]>,
    pub r#type: Type,
    pub class: Class,
    pub ttl: u32,
    pub rd_length: u16,
    pub data: Record<'a>,
}

#[derive(Debug)]
pub enum Record<'a> {
    /// DNS A record field layout as per [RFC 1035 Section 3.4.1](https://www.rfc-editor.org/rfc/rfc1035#section-3.4.1)
    ///
    /// ```text
    ///   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                    ADDRESS                    |
    /// |                                               |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    A {
        address: &'a [u8; 4],
    },

    /// DNS NS record field layout as per [RFC 1035 Section 3.3.11](https://www.rfc-editor.org/rfc/rfc1035#section-3.3.11)
    ///
    /// ```text
    ///   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// /                   NSDNAME                     /
    /// /                                               /
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    NS {
        nsdname: Vec<&'a [u8]>,
    },

    /// DNS CNAME record field layout as per [RFC 1035 Section 3.3.1](https://www.rfc-editor.org/rfc/rfc1035#section-3.3.1)
    ///
    /// ```text
    ///   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// /                     CNAME                     /
    /// /                                               /
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    CNAME {
        cname: Vec<&'a [u8]>,
    },

    /// DNS SOA record field layout as per [RFC 1035 Section 3.3.13](https://www.rfc-editor.org/rfc/rfc1035#section-3.3.13)
    ///
    /// ```text
    ///   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// /                     MNAME                     /
    /// /                                               /
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// /                     RNAME                     /
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                    SERIAL                     |
    /// |                                               |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                    REFRESH                    |
    /// |                                               |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                     RETRY                     |
    /// |                                               |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                    EXPIRE                     |
    /// |                                               |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                    MINIMUM                    |
    /// |                                               |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    SOA {
        mname: Vec<&'a [u8]>,
        rname: Vec<&'a [u8]>,
        serial: u32,
        refresh: u32,
        retry: u32,
        expire: u32,
        minimum: u32,
    },

    /// DNS PTR record field layout as per [RFC 1035 Section 3.3.12](https://www.rfc-editor.org/rfc/rfc1035#section-3.3.12)
    ///
    /// ```text
    ///   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// /                   PTRDNAME                    /
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    PTR {
        ptrdname: Vec<&'a [u8]>,
    },

    /// DNS MX record field layout as per [RFC 1035 Section 3.3.9](https://www.rfc-editor.org/rfc/rfc1035#section-3.3.9)
    ///
    /// ```text
    ///   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                  PREFERENCE                   |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// /                   EXCHANGE                    /
    /// /                                               /
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    MX {
        preference: u16,
        exchange: Vec<&'a [u8]>,
    },

    /// DNS TXT record field layout as per [RFC 1035 Section 3.3.14](https://www.rfc-editor.org/rfc/rfc1035#section-3.3.14)
    ///
    /// ```text
    ///   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// /                   TXT-DATA                    /
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    TXT {
        text: &'a [u8],
    },

    /// DNS AAAA record field layout as per [RFC 3596 Section 2.2](https://www.rfc-editor.org/rfc/rfc3596#section-2.2)
    ///
    /// ```text
    ///   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// |                    ADDRESS                    |
    /// |                                               |
    /// |                                               |
    /// |                                               |
    /// |                                               |
    /// |                                               |
    /// |                                               |
    /// |                                               |
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    AAAA {
        address: &'a [u8; 16],
    },

    Unkown {
        data: &'a [u8],
    },
}
