use aes::cipher::InvalidLength;
use inout::block_padding::UnpadError;
use std::io;
use std::str::Utf8Error;
use thiserror::Error;

#[derive(Error, Debug)]
#[error("{0}")]
pub enum ErrorKind {
    Base64DecodeError(#[from] base64::DecodeError),
    JsonError(#[from] serde_json::error::Error),
    SystemTimeError(#[from] std::time::SystemTimeError),
    TcpError(#[from] io::Error),
    Utf8Error(#[from] Utf8Error),

    InvalidKeyLength(#[from] InvalidLength),
    UnpadError(#[from] UnpadError),

    #[error("parsing failed with: {0:?}")]
    ParseError(nom::error::ErrorKind),
    #[error("Something went wrong when parsing the received buffer. It still contains data after parsing is done")]
    BufferNotCompletelyParsedError,
    #[error("Can not encode messages that are missing CommandType")]
    CanNotEncodeMessageWithoutCommand,
    #[error("No CommandType was supplied in message")]
    CommandTypeMissing,
    #[error("Error: CRC mismatch")]
    CRCError,
    #[error("Missing Tuya key")]
    MissingKey,
    #[error("The key length is {0}, should be 16")]
    KeyLength(usize),
    #[error("the tuyadevice is not created with a socket address. can not set object")]
    MissingAddressError,
    #[error("Data was incomplete. Error while parsing the received data")]
    ParsingIncomplete,
    #[error("Bad read from TcpStream")]
    BadTcpRead,
    #[error("The given version {0} is not valid")]
    VersionError(String),
    #[error("SessKeyNegResp message did not contain remote key")]
    MissingRemoteKey,
    #[error("SessKeyNegResp message does not contain a valid remote key")]
    InvalidRemoteKey,
    #[error("Not connected to device")]
    NotConnected,
}
