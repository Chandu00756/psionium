use thiserror::Error;

/// Everything that can go wrong while handling keys or `.psen` files.
#[derive(Debug, Error)]
pub enum Error {
    /// Reading or writing failed.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    /// The input is not a well-formed `.psen` v2 file.
    #[error("not a valid .psen v2 file: {0}")]
    Format(&'static str),
    /// The file uses a version or suite this build does not support.
    #[error("unsupported {0}")]
    Unsupported(&'static str),
    /// A key could not be parsed or is the wrong size for its suite.
    #[error("invalid key: {0}")]
    Key(&'static str),
    /// No recipient stanza in the file opens with this identity.
    #[error("this identity is not a recipient of the file")]
    NotARecipient,
    /// The header authentication tag does not match.
    #[error("the file header has been modified or is corrupt")]
    HeaderAuth,
    /// A payload chunk failed authentication.
    #[error("chunk {0} is corrupt, or the file was truncated or extended")]
    ChunkAuth(u64),
    /// The file ended before the payload's final chunk.
    #[error("the file is truncated")]
    Truncated,
    /// Recipients were given with different suites.
    #[error("all recipients must use the same suite")]
    MixedSuites,
    /// No recipients were given.
    #[error("at least one recipient is required")]
    NoRecipients,
    /// More recipients than the format allows.
    #[error("too many recipients (at most {max})")]
    TooManyRecipients {
        /// The largest number of recipients a file can have.
        max: usize,
    },
    /// A chunk size outside the allowed range was requested.
    #[error("chunk size must be between 2^12 and 2^24 bytes")]
    ChunkSize,
    /// A cryptographic primitive reported failure.
    #[error("a cryptographic operation failed")]
    Crypto,
}

impl From<aws_lc_rs::error::Unspecified> for Error {
    fn from(_: aws_lc_rs::error::Unspecified) -> Self {
        Error::Crypto
    }
}

/// Result type used throughout the crate.
pub type Result<T> = std::result::Result<T, Error>;
