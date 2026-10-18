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

/// The result of trying to parse a handshake from the start of a connection.
#[derive(Debug)]
pub enum ParseResult {
    /// More bytes are needed before the handshake can be parsed.
    Incomplete,
    /// The bytes do not look like a handshake.
    Unrecognized,
    Handshake(UnifiedHandshakeFormat),
}

impl UnifiedHandshakeFormat {
    /// Tries to parse a Unified Handshake Format from the start of the given bytes.
    ///
    /// Only the first packet is looked at, so any packets following the handshake (e.g. the status
    /// request or login start, which clients often send in the same TCP segment) are ignored.
    pub fn from_bytes(bytes: &[u8]) -> ParseResult {
        let mut buf = Buffer::new(bytes);

        const PRE_1_7_PROTOCOL_MAGIC: [u8; 3] = [0xfe, 0x01, 0xfa];
        let Ok(peek) = buf.peek(3) else {
            return ParseResult::Incomplete;
        };

        if peek == PRE_1_7_PROTOCOL_MAGIC {
            // magic + "MC|PingHost" as a UTF-16 string + 2 byte payload length
            const HEADER_LEN: usize = 3 + 2 + 11 * 2 + 2;
            let Ok(header) = buf.advance(HEADER_LEN) else {
                return ParseResult::Incomplete;
            };
            let payload_length =
                u16::from_be_bytes([header[HEADER_LEN - 2], header[HEADER_LEN - 1]]) as usize;
            let Ok(payload) = buf.advance(payload_length) else {
                return ParseResult::Incomplete;
            };

            return match Self::parse_pre_1_7(header, payload) {
                Ok(handshake) => ParseResult::Handshake(handshake),
                Err(_) => ParseResult::Unrecognized,
            };
        }

        // Assume modern handshake format
        let packet_length = match buf.next_varint() {
            Ok(length) => length,
            // a varint is at most 5 bytes long, so if we had more than that, it is malformed
            Err(_) if bytes.len() > 5 => return ParseResult::Unrecognized,
            Err(_) => return ParseResult::Incomplete,
        };
        let Ok(packet_length) = usize::try_from(packet_length) else {
            return ParseResult::Unrecognized;
        };

        // bail out early on anything that isn't a handshake packet (id 0x00) instead of waiting
        // for `packet_length` bytes that may never come (e.g. a short HTTP request)
        match buf.peek(1) {
            Ok([0x00]) => {}
            Ok(_) => return ParseResult::Unrecognized,
            Err(_) => return ParseResult::Incomplete,
        }

        let Ok(packet) = buf.advance(packet_length) else {
            return ParseResult::Incomplete;
        };

        match Self::parse_modern(packet) {
            Ok(handshake) => ParseResult::Handshake(handshake),
            Err(_) => ParseResult::Unrecognized,
        }
    }

    /// Parses a pre-1.7 server list ping, given its fixed-size header and its payload.
    fn parse_pre_1_7(header: &[u8], payload: &[u8]) -> anyhow::Result<Self> {
        let mut header = Buffer::new(&header[3..]);
        let message = header.next_string_utf16()?;
        if message != "MC|PingHost" {
            anyhow::bail!(
                "malformed pre-1.7 handshake: unexpected message '{}'",
                message
            );
        }

        let mut buf = Buffer::new(payload);
        let _protocol_version = buf.advance(1)?; // 1 byte protocol version

        let hostname = buf.next_string_utf16()?;
        // last 4 bytes are the port
        let _port = u32::from_be_bytes(buf.next_n::<4>().context("failed to read port")?);

        // if there are any bytes left, the handshake is probably not a handshake
        if buf.left() != 0 {
            anyhow::bail!("trailing bytes in pre-1.7 handshake");
        }

        Ok(UnifiedHandshakeFormat { hostname })
    }

    /// Parses a modern handshake packet, excluding the packet length prefix.
    fn parse_modern(packet: &[u8]) -> anyhow::Result<Self> {
        let mut buf = Buffer::new(packet);

        let _packet_id = buf.next_varint()?;
        let _protocol_version = buf.next_varint()?;

        let hostname = buf.next_string_utf8()?;
        let _port = u16::from_be_bytes(buf.next_n::<2>()?);
        let _next_state = buf.next_varint()?;

        // if there are any bytes left, the handshake is probably not a handshake
        if buf.left() != 0 {
            anyhow::bail!("trailing bytes in handshake");
        }

        Ok(UnifiedHandshakeFormat { hostname })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Builds a modern handshake packet for `hostname`.
    fn modern_handshake(hostname: &str) -> Vec<u8> {
        let mut packet = vec![0x00, 0xff, 0x05]; // packet id, protocol version 767 (varint)
        packet.push(hostname.len() as u8);
        packet.extend_from_slice(hostname.as_bytes());
        packet.extend_from_slice(&25565u16.to_be_bytes());
        packet.push(0x01); // next state: status

        let mut framed = vec![packet.len() as u8];
        framed.extend(packet);
        framed
    }

    fn utf16_string(s: &str) -> Vec<u8> {
        let units: Vec<u16> = s.encode_utf16().collect();
        let mut out = (units.len() as u16).to_be_bytes().to_vec();
        out.extend(units.iter().flat_map(|u| u.to_be_bytes()));
        out
    }

    fn pre_1_7_ping(hostname: &str) -> Vec<u8> {
        let mut payload = vec![74]; // protocol version
        payload.extend(utf16_string(hostname));
        payload.extend_from_slice(&25565u32.to_be_bytes());

        let mut out = vec![0xfe, 0x01, 0xfa];
        out.extend(utf16_string("MC|PingHost"));
        out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        out.extend(payload);
        out
    }

    fn hostname(result: ParseResult) -> String {
        match result {
            ParseResult::Handshake(handshake) => handshake.hostname,
            other => panic!("expected handshake, got {other:?}"),
        }
    }

    #[test]
    fn modern_handshake_alone() {
        let bytes = modern_handshake("mc.example.com");
        assert_eq!(
            hostname(UnifiedHandshakeFormat::from_bytes(&bytes)),
            "mc.example.com"
        );
    }

    #[test]
    fn modern_handshake_followed_by_status_request() {
        let mut bytes = modern_handshake("mc.example.com");
        bytes.extend_from_slice(&[0x01, 0x00]);
        assert_eq!(
            hostname(UnifiedHandshakeFormat::from_bytes(&bytes)),
            "mc.example.com"
        );
    }

    #[test]
    fn modern_handshake_followed_by_login_start() {
        let mut bytes = modern_handshake("mc.example.com");
        bytes.extend_from_slice(&[0x08, 0x00, 0x06, b'S', b't', b'e', b'v', b'e', b'!']);
        assert_eq!(
            hostname(UnifiedHandshakeFormat::from_bytes(&bytes)),
            "mc.example.com"
        );
    }

    #[test]
    fn modern_handshake_truncated() {
        let bytes = modern_handshake("mc.example.com");
        for len in 0..bytes.len() {
            assert!(
                matches!(
                    UnifiedHandshakeFormat::from_bytes(&bytes[..len]),
                    ParseResult::Incomplete
                ),
                "expected incomplete at length {len}"
            );
        }
    }

    #[test]
    fn pre_1_7_ping_alone() {
        let bytes = pre_1_7_ping("mc.example.com");
        assert_eq!(
            hostname(UnifiedHandshakeFormat::from_bytes(&bytes)),
            "mc.example.com"
        );
    }

    #[test]
    fn pre_1_7_ping_truncated() {
        let bytes = pre_1_7_ping("mc.example.com");
        for len in 0..bytes.len() {
            assert!(
                matches!(
                    UnifiedHandshakeFormat::from_bytes(&bytes[..len]),
                    ParseResult::Incomplete
                ),
                "expected incomplete at length {len}"
            );
        }
    }

    #[test]
    fn http_request_is_unrecognized() {
        let bytes = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        assert!(matches!(
            UnifiedHandshakeFormat::from_bytes(bytes),
            ParseResult::Unrecognized
        ));
    }
}
