#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum IncomingDirection {
    /// Ex. socks5 server
    FromServer,
    FromClient,
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum OutgoingDirection {
    /// Ex. socks5 server
    ToServer,
    ToClient,
}

#[derive(Clone, Copy, Eq, PartialEq, Debug)]
pub enum Direction {
    Incoming(IncomingDirection),
    Outgoing(OutgoingDirection),
}

#[derive(Clone, Eq, PartialEq, Debug)]
pub struct DataEvent<'a, T> {
    pub direction: T,
    pub buffer: &'a [u8],
}

pub type IncomingDataEvent<'a> = DataEvent<'a, IncomingDirection>;
pub type OutgoingDataEvent<'a> = DataEvent<'a, OutgoingDirection>;
