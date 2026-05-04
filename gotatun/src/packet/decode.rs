use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};

use crate::packet::Packet;

pub trait DecodeAs<Target: FromBytes + ?Sized>: IntoBytes + Immutable {
    type Decoder;

    /// Validate that `Self` is a valid instance of `Target`.
    ///
    /// The returned `usize` indicated the byte-wise length of `Target`,
    /// since it may be smaller than `Self`.
    fn validate(&self, d: Self::Decoder) -> Result<usize, DecodeError>;
}

// TODO: make pretty
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("Invalid IP version")]
    InvalidIpVersion,
    #[error("Header Too Small")]
    HeaderTooSmall,
    #[error("Header Too Big")]
    HeaderTooBig,
    #[error("Bad Checksum")]
    BadChecksum,
    #[error("Invalid protocol")]
    InvalidProtocol,
    #[error("BALHALHALHLH")]
    Etc,
    #[error("Invalid value for {0}")]
    InvalidValue(&'static str),
    // zerocopy errors
    #[error("Bad alignment")]
    BadAlignment,
    #[error("Invalid something something")]
    Invalid,
}

impl<S, D: ?Sized + TryFromBytes> From<zerocopy::TryCastError<S, D>> for DecodeError {
    fn from(value: zerocopy::TryCastError<S, D>) -> Self {
        match value {
            zerocopy::TryCastError::Alignment(..) => DecodeError::BadAlignment,
            zerocopy::TryCastError::Size(..) => DecodeError::HeaderTooSmall, // TODO: can technically be toobig also
            zerocopy::TryCastError::Validity(..) => DecodeError::Invalid,
        }
    }
}

pub fn decode_ref<V, T>(source: &V, validator: V::Decoder) -> Result<&T, DecodeError>
where
    V: DecodeAs<T> + ?Sized,
    T: FromBytes + KnownLayout + Immutable + ?Sized,
{
    let len = source.validate(validator)?;
    let bytes = &source.as_bytes()[..len];
    Ok(T::try_ref_from_bytes(bytes)?)
}

pub fn decode_mut<V, T>(source: &mut V, validator: V::Decoder) -> Result<&mut T, DecodeError>
where
    V: DecodeAs<T> + FromBytes + ?Sized,
    T: IntoBytes + FromBytes + KnownLayout + Immutable + ?Sized,
{
    let len = source.validate(validator)?;
    let bytes = &mut source.as_mut_bytes()[..len];
    Ok(T::try_mut_from_bytes(bytes)?)
}

pub fn decode_owned<V, T>(
    source: Packet<V>,
    validator: V::Decoder,
) -> Result<Packet<T>, DecodeError>
where
    V: DecodeAs<T> + FromBytes + ?Sized + super::CheckedPayload,
    T: IntoBytes + FromBytes + KnownLayout + Immutable + super::CheckedPayload + ?Sized,
{
    let len = source.validate(validator)?;
    let mut source = source.into_bytes();
    source.truncate(len);
    Ok(source.cast())
}
