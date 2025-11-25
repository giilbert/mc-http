use anyhow::Context;

/// A simple buffer wrapper to help with parsing.
struct Buffer<'a> {
    current: &'a [u8],
}

impl<'a> Buffer<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Self { current: data }
    }

    /// Advances the buffer by `n` bytes, returning a slice of the advanced bytes.
    pub fn advance(&mut self, n: usize) -> anyhow::Result<&'a [u8]> {
        if self.current.len() < n {
            return Err(anyhow::anyhow!("unexpected end of buffer while advancing"));
        }

        let result = &self.current[..n];
        self.current = &self.current[n..];

        Ok(result)
    }

    /// Peeks at the next `n` bytes without advancing the buffer.
    pub fn peek(&self, n: usize) -> anyhow::Result<&'a [u8]> {
        if self.current.len() < n {
            return Err(anyhow::anyhow!("unexpected end of buffer while peeking"));
        }

        Ok(&self.current[..n])
    }

    /// Advances the buffer and reads the next byte.
    pub fn next_byte(&mut self) -> anyhow::Result<u8> {
        let byte = self.advance(1)?[0];
        Ok(byte)
    }

    /// Advances the buffer and reads the next N bytes as an array.
    pub fn next_n<const N: usize>(&mut self) -> anyhow::Result<[u8; N]> {
        let bytes = self.advance(N)?;
        let array: &[u8; N] = bytes
            .try_into()
            .map_err(|e| anyhow::anyhow!("failed to read {} bytes: {}", N, e))?;
        Ok(*array)
    }

    /// Returns the number of bytes left in the buffer.
    pub fn left(&self) -> usize {
        self.current.len()
    }

    /// Reads a VarInt from the beginning of the buffer, advancing the buffer.
    fn next_varint(&mut self) -> anyhow::Result<i32> {
        let mut num_read = 0;
        let mut result = 0;

        loop {
            let byte = self.next_byte()?;

            // only the lower 7 bits are part of the value
            let value = (byte & 0b0111_1111) as i32;
            result |= value << (7 * num_read);

            num_read += 1;
            if num_read > 5 {
                return Err(anyhow::anyhow!("varint is too big"));
            }

            // most significant bit indicates if there are more bytes to read
            if (byte & 0b1000_0000) == 0 {
                break;
            }
        }

        Ok(result)
    }

    /// Reads a UTF-16 string from the buffer, advancing the buffer.
    pub fn next_string_utf16(&mut self) -> anyhow::Result<String> {
        // string length is encoded as utf-16 code units
        let str_len = u16::from_be_bytes(self.next_n()?) as usize * 2;

        let string_bytes = self.advance(str_len)?;
        if string_bytes.len() % 2 != 0 {
            return Err(anyhow::anyhow!("invalid UTF-8 string: odd number of bytes"));
        }

        let string = String::from_utf16(
            &string_bytes
                .chunks(2)
                .map(|chunk| u16::from_be_bytes([chunk[0], chunk[1]]))
                .collect::<Vec<u16>>(),
        )
        .context("invalid UTF-16 string")?;

        Ok(string)
    }

    /// Read a UTF-8 string from the buffer, advancing the buffer.
    pub fn next_string_utf8(&mut self) -> anyhow::Result<String> {
        let str_len = self.next_varint()? as usize;

        let string_bytes = self.advance(str_len)?;
        let string = String::from_utf8(string_bytes.to_vec()).context("invalid UTF-8 string")?;

        Ok(string)
    }
}

#[derive(Debug)]
pub struct UnifiedHandshakeFormat {
    pub hostname: String,
    // pub port: u16,
}

impl UnifiedHandshakeFormat {
    /// Tries to parse a Unified Handshake Format from the given bytes.
    ///
    /// If the bytes do not represent a valid handshake, Ok(None) is returned.
    pub fn from_bytes(bytes: &[u8]) -> anyhow::Result<Option<Self>> {
        let mut buf = Buffer::new(bytes);

        const PRE_1_7_PROTOCOL_MAGIC: [u8; 3] = [0xfe, 0x01, 0xfa];
        let peek = buf.peek(3)?;
        if peek == PRE_1_7_PROTOCOL_MAGIC {
            let _magic = buf.advance(PRE_1_7_PROTOCOL_MAGIC.len())?;

            let message = buf.next_string_utf16()?;
            if message != "MC|PingHost" {
                anyhow::bail!(
                    "malformed pre-1.7 handshake: unexpected message '{}'",
                    message
                );
            }

            // next 2 bytes are the length of the rest of the payload
            let _payload_length = u16::from_be_bytes(
                buf.advance(2)?
                    .try_into()
                    .context("failed to read payload length")?,
            );
            let _protocol_version = buf.advance(1)?; // 1 byte protocol version

            let hostname = buf.next_string_utf16()?;
            // last 4 bytes are the port
            let _port = u32::from_be_bytes(buf.next_n::<4>().context("failed to read port")?);

            // if there are any bytes left, the handshake is probably not a handshake
            if buf.left() != 0 {
                return Ok(None);
            }

            return Ok(Some(UnifiedHandshakeFormat { hostname }));
        }

        // Assume modern handshake format
        let _packet_length = buf.next_varint()?;
        let _packet_id = buf.next_varint()?;
        let _protocol_version = buf.next_varint()?;

        let hostname = buf.next_string_utf8()?;
        let _port = u16::from_be_bytes(buf.next_n::<2>()?);
        let _next_state = buf.next_varint()?;

        // if there are any bytes left, the handshake is probably not a handshake
        if buf.left() != 0 {
            return Ok(None);
        }

        Ok(Some(UnifiedHandshakeFormat { hostname }))
    }
}
