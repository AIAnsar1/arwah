#[derive(Debug, PartialEq)]
pub enum ArwahCentrifugeError {
    WrongProtocol,
    ParsingError,
    UnknownProtocol,
    InvalidPacket,
}

#[derive(Debug)]
pub enum ArwahNoiseLevel {
    Zero = 0,
    One = 1,
    Two = 2,
    AlmostMaximum = 3,
    Maximum = 4,
}

impl ArwahNoiseLevel {
    pub fn arwah_into_u8(self) -> u8 {
        self as u8
    }
}
