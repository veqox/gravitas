use std::u16;

use crate::{DomainName, class::Class, r#type::Type};

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
pub enum ResourceRecord<'a> {
    Record {
        name: DomainName<'a>,
        ttl: u32,
        data: Record<'a>,
    },
    OPTRecord {
        size: u16,
        flags: u32,
        options: Vec<Option<'a>>,
    },
    Unknown {
        name: DomainName<'a>,
        r#type: Type,
        class: Class,
        ttl: u32,
        data: &'a [u8],
    },
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
    A { address: &'a [u8; 4] },

    /// DNS NS record field layout as per [RFC 1035 Section 3.3.11](https://www.rfc-editor.org/rfc/rfc1035#section-3.3.11)
    ///
    /// ```text
    ///   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// /                   NSDNAME                     /
    /// /                                               /
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    NS { nsdname: DomainName<'a> },

    /// DNS CNAME record field layout as per [RFC 1035 Section 3.3.1](https://www.rfc-editor.org/rfc/rfc1035#section-3.3.1)
    ///
    /// ```text
    ///   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// /                     CNAME                     /
    /// /                                               /
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    CNAME { cname: DomainName<'a> },

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
        mname: DomainName<'a>,
        rname: DomainName<'a>,
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
    PTR { ptrdname: DomainName<'a> },

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
        exchange: DomainName<'a>,
    },

    /// DNS TXT record field layout as per [RFC 1035 Section 3.3.14](https://www.rfc-editor.org/rfc/rfc1035#section-3.3.14)
    ///
    /// ```text
    ///   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// /                   TXT-DATA                    /
    /// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
    /// ```
    TXT { text: &'a [u8] },

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
    AAAA { address: &'a [u8; 16] },
}

impl<'a> Record<'a> {
    pub fn size(&self) -> usize {
        match self {
            Self::A { address } => address.len(),
            Self::NS { nsdname } => nsdname.size(),
            Self::CNAME { cname } => cname.size(),
            Self::SOA { mname, rname, .. } => {
                mname.size()
                    + rname.size()
                    + size_of::<u32>()
                    + size_of::<u32>()
                    + size_of::<u32>()
                    + size_of::<u32>()
                    + size_of::<u32>()
            }
            Self::PTR { ptrdname } => ptrdname.size(),
            Self::MX { exchange, .. } => size_of::<u16>() + exchange.size(),
            Self::TXT { text } => text.len(),
            Self::AAAA { address } => address.len(),
        }
    }
}

/// DNS OPT pseudo rr field layout as per [RFC 6891 Section 6.1.2](https://www.rfc-editor.org/rfc/rfc6891#section-6.1.2)
///
/// ```text
///   0  1  2  3  4  5  6  7  8  9 10 11 12 13 14 15
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                   OPTION-CODE                 |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                  OPTION-LENGTH                |
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// |                                               |
/// /                   OPTION-DATA                 /
/// /                                               /
/// +--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+--+
/// ```
#[derive(Debug)]
pub enum Option<'a> {
    Unknown {
        code: OptionCode,
        len: u16,
        data: &'a [u8],
    },
}

impl Option<'_> {
    pub fn size(&self) -> usize {
        match self {
            Self::Unknown { data, .. } => size_of::<u16>() + size_of::<u16>() + data.len(),
        }
    }
}

#[allow(clippy::upper_case_acronyms)]
#[derive(Debug)]
pub enum OptionCode {
    /// [RFC 6891](https://www.rfc-editor.org/rfc/rfc6891)
    Zero,

    /// [RFC 8764](https://www.rfc-editor.org/rfc/rfc8764)
    LLQ,

    /// [UL](https://datatracker.ietf.org/doc/draft-ietf-dnssd-update-lease/09/)
    UL,

    /// [RFC 5001](https://www.rfc-editor.org/rfc/rfc5001)
    NSID,

    /// [RFC 6975](https://www.rfc-editor.org/rfc/rfc6975)
    DAU,

    /// [RFC 6975](https://www.rfc-editor.org/rfc/rfc6975)
    DHU,

    /// [RFC 6975](https://www.rfc-editor.org/rfc/rfc6975)
    N3U,

    /// [RFC 7871](https://www.rfc-editor.org/rfc/rfc7871)
    Subnet,

    /// [RFC 7314](https://www.rfc-editor.org/rfc/rfc7314)
    Expire,

    /// [RFC 7873](https://www.rfc-editor.org/rfc/rfc7873)
    Cookie,

    /// [RFC 7828](https://www.rfc-editor.org/rfc/rfc7828)
    Keepalive,

    /// [RFC 7830](https://www.rfc-editor.org/rfc/rfc7830)
    Padding,

    /// [RFC 7901](https://www.rfc-editor.org/rfc/rfc7901)
    Chain,

    /// [RFC 8914](https://www.rfc-editor.org/rfc/rfc8914)
    ExtendedError,

    /// [RFC 9567](https://www.rfc-editor.org/rfc/rfc9567)
    ReportChannel,

    /// [RFC 9660](https://www.rfc-editor.org/rfc/rfc9660)
    ZoneVersion,

    Unknown(u16),
}

impl From<u16> for OptionCode {
    fn from(value: u16) -> Self {
        match value {
            0 => Self::Zero,
            1 => Self::LLQ,
            2 => Self::UL,
            3 => Self::NSID,
            5 => Self::DAU,
            6 => Self::DHU,
            7 => Self::N3U,
            8 => Self::Subnet,
            9 => Self::Expire,
            10 => Self::Cookie,
            11 => Self::Keepalive,
            12 => Self::Padding,
            13 => Self::Chain,
            15 => Self::ExtendedError,
            18 => Self::ReportChannel,
            19 => Self::ZoneVersion,
            x => Self::Unknown(x),
        }
    }
}

impl From<OptionCode> for u16 {
    fn from(value: OptionCode) -> Self {
        match value {
            OptionCode::Zero => 0,
            OptionCode::LLQ => 1,
            OptionCode::UL => 2,
            OptionCode::NSID => 3,
            OptionCode::DAU => 5,
            OptionCode::DHU => 6,
            OptionCode::N3U => 7,
            OptionCode::Subnet => 8,
            OptionCode::Expire => 9,
            OptionCode::Cookie => 10,
            OptionCode::Keepalive => 11,
            OptionCode::Padding => 12,
            OptionCode::Chain => 13,
            OptionCode::ExtendedError => 15,
            OptionCode::ReportChannel => 18,
            OptionCode::ZoneVersion => 19,
            OptionCode::Unknown(x) => x,
        }
    }
}
