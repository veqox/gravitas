#[derive(Debug)]
pub enum ParseError {
    BufferOverflow(usize, usize),
    InvalidLabelLength(usize),
    FormatError,
    InvalidUtf8,
    NotImplemented,
}

#[derive(Debug)]
pub struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn seek(&mut self, pos: usize) -> Result<(), ParseError> {
        if pos > self.buf.len() {
            return Err(ParseError::BufferOverflow(self.pos, self.buf.len()));
        }

        self.pos = pos;

        Ok(())
    }

    pub fn consume_u32(&mut self) -> Result<u32, ParseError> {
        Ok(u32::from_be_bytes([
            self.consume_u8()?,
            self.consume_u8()?,
            self.consume_u8()?,
            self.consume_u8()?,
        ]))
    }

    pub fn consume_u16(&mut self) -> Result<u16, ParseError> {
        Ok(u16::from_be_bytes([self.consume_u8()?, self.consume_u8()?]))
    }

    pub fn consume_u8(&mut self) -> Result<u8, ParseError> {
        let value = self.read_u8()?;
        self.pos += size_of::<u8>();
        Ok(value)
    }

    pub fn read_u8(&self) -> Result<u8, ParseError> {
        if self.pos >= self.buf.len() {
            return Err(ParseError::BufferOverflow(self.pos, self.buf.len()));
        }

        Ok(self.buf[self.pos])
    }

    pub fn consume_bytes(&mut self, len: usize) -> Result<&'a [u8], ParseError> {
        if self.pos + len > self.buf.len() {
            return Err(ParseError::BufferOverflow(self.pos + len, self.buf.len()));
        }

        let bytes = &self.buf[self.pos..self.pos + len];
        self.pos += len;
        Ok(bytes)
    }
}

pub trait Parse<'a>: Sized {
    fn parse(parser: &mut Parser<'a>) -> Result<Self, ParseError>;
}
