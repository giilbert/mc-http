use std::fmt::Debug;

pub const OPERATION_ACCEPT: u64 = 1;

/// A token representing a specific io_uring operation.
///
/// To get a `u64` user data value for io_uring operations, use `token.id()`. The user data value is
/// laid out as such:
/// - Bits 0-47: Token ID
/// - Bits 48-63: Operation Type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Token {
    Accept { socket_id: u32 },
}

impl Token {
    pub fn id(&self) -> u64 {
        match self {
            Token::Accept { socket_id: socket } => *socket as u64,
        }
    }

    pub fn operation(&self) -> u64 {
        match self {
            Token::Accept { .. } => OPERATION_ACCEPT,
        }
    }

    /// Converts the token into a `u64` suitable for use as io_uring user data.
    pub fn user_data(&self) -> u64 {
        let id = self.id();
        let operation = self.operation();
        (id & 0x0000_FFFF_FFFF_FFFF) | ((operation as u64) << 48)
    }
}

impl Into<u64> for Token {
    fn into(self) -> u64 {
        self.user_data()
    }
}

impl From<u64> for Token {
    fn from(user_data: u64) -> Self {
        let id = user_data & 0x0000_FFFF_FFFF_FFFF;
        let operation = (user_data >> 48) & 0x0000_0000_0000_FFFF;

        match operation {
            OPERATION_ACCEPT => Token::Accept {
                socket_id: id as u32,
            },
            _ => panic!("unknown operation type in user data: {}", operation),
        }
    }
}
