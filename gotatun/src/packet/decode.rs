use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, TryFromBytes};

use crate::packet::Packet;

use super::CheckedPayload;

/// A trait that enables byte-wise conversion between one packet type and another through zerocopy.
///
/// # Validation
/// This trait asserts, at minimum, that `Self` can be transmuted into `Target`, but
/// does not necessarily assert that the value resulting from the conversion is sane.
///
/// [`DecodeAs::validate`] _should_ perform validation, subject to configuration by the [`DecodeAs::Decoder`].
pub trait Decoder<Src, Dst>
where
    Src: IntoBytes + Immutable + KnownLayout + ?Sized,
    Dst: TryFromBytes + Immutable + KnownLayout + ?Sized,
{
    /// Validate that `Self` is a valid instance of `Target`.
    ///
    /// The returned `usize` indicated the byte-wise length of `Target`,
    /// since it may be smaller than `Self`.
    fn validate(&self, s: &Src) -> Result<usize, DecodeError>;

    /// Try to decode the `&Src` packet as `&Dst`.
    ///
    /// `Src` must be decodeable as `Dst` using [`DecodeAs`].
    ///
    /// See also: [`decode_mut`], [`decode_owned`].
    fn decode_ref<'a>(&self, source: &'a Src) -> Result<&'a Dst, DecodeError> {
        let len = self.validate(source)?;
        let bytes = &source.as_bytes()[..len];
        Ok(Dst::try_ref_from_bytes(bytes)?)
    }

    /// Try to decode the `&mut Src` packet as `&mut Dst`.
    ///
    /// `Src` must be decodeable as `Dst` using [`DecodeAs`].
    ///
    /// See also: [`decode_ref`], [`decode_owned`].
    fn decode_mut<'a>(&self, source: &'a mut Src) -> Result<&'a mut Dst, DecodeError>
    where
        Src: FromBytes,
        Dst: IntoBytes,
    {
        let len = self.validate(source)?;
        let bytes = &mut source.as_mut_bytes()[..len];
        Ok(Dst::try_mut_from_bytes(bytes)?)
    }

    /// Try to decode the `Packet<Src>` packet as `Packet<Dst>`.
    ///
    /// `Src` must be decodeable as `Dst` using [`DecodeAs`].
    ///
    /// See also: [`decode_ref`], [`decode_mut`].
    fn decode_owned(&self, source: Packet<Src>) -> Result<Packet<Dst>, DecodeError>
    where
        Src: CheckedPayload,
        Dst: CheckedPayload,
    {
        let len = self.validate(&*source)?;
        let mut source = source.into_bytes();
        source.truncate(len);
        Ok(source.cast())
    }
}

/// An error returned by [`decode_ref`] and friends.
#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("Invalid value for {0}")]
    InvalidValue(&'static str),
    // zerocopy errors
    #[error("Bad alignment")]
    BadAlignment,
    #[error("Invalid source size")]
    InvalidSourceSize,
    #[error("Invalid source data")]
    InvalidSourceData,
}

impl<S, D: ?Sized + TryFromBytes> From<zerocopy::TryCastError<S, D>> for DecodeError {
    fn from(value: zerocopy::TryCastError<S, D>) -> Self {
        match value {
            zerocopy::TryCastError::Alignment(..) => DecodeError::BadAlignment,
            zerocopy::TryCastError::Size(..) => DecodeError::InvalidSourceSize,
            zerocopy::TryCastError::Validity(..) => DecodeError::InvalidSourceData,
        }
    }
}
