#[derive(Debug)]
pub enum SerializeError {
    BufferOverflow(usize, usize),
    InvalidLabelLength(usize),
}

pub struct Serializer<'a> {
    buf: &'a mut [u8; 4096],
    pos: usize,
}

impl<'a> Serializer<'a> {
    pub fn new(buf: &'a mut [u8; 4096]) -> Self {
        Self { buf, pos: 0 }
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn write_u32(&mut self, value: u32) -> Result<(), SerializeError> {
        self.write_bytes(&value.to_be_bytes())
    }

    pub fn write_u16(&mut self, value: u16) -> Result<(), SerializeError> {
        self.write_bytes(&value.to_be_bytes())
    }

    pub fn write_u8(&mut self, value: u8) -> Result<(), SerializeError> {
        self.write_bytes(&value.to_be_bytes())
    }

    pub fn write_bytes(&mut self, bytes: &[u8]) -> Result<(), SerializeError> {
        if self.pos + bytes.len() >= self.buf.len() {
            return Err(SerializeError::BufferOverflow(
                self.pos + bytes.len(),
                self.buf.len(),
            ));
        }

        self.buf[self.pos..self.pos + bytes.len()].copy_from_slice(&bytes);
        self.pos += bytes.len();

        Ok(())
    }
}

pub trait Serialize<'a>: Sized {
    fn serialize(self, serializer: &mut Serializer<'a>) -> Result<usize, SerializeError>;
}
