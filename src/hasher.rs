use crate::error::Error;
use core::fmt::Debug;

/// Stack allocated digest trait.
pub trait Digest<const S: usize>:
    AsRef<[u8]>
    + AsMut<[u8]>
    + From<[u8; S]>
    + Into<[u8; S]>
    + Clone
    + core::hash::Hash
    + Debug
    + Default
    + Eq
    + Send
    + Sync
    + 'static
{
    /// Size of the digest. Maximum for Some of the Blake family is 2^64-1 bytes
    const SIZE: usize = S;

    /// Wraps the digest bytes.
    fn wrap(digest: &[u8]) -> Result<Self, Error> {
        if digest.len() != S {
            return Err(Error::InvalidSize(digest.len() as _));
        }
        let mut array = [0; S];
        let len = digest.len().min(array.len());
        array[..len].copy_from_slice(&digest[..len]);
        Ok(array.into())
    }

    /// Reads a multihash digest from a byte stream that contains the digest prefixed with the size.
    ///
    /// The byte stream must not contain the code as prefix.
    #[cfg(feature = "std")]
    fn from_reader<R>(mut r: R) -> Result<Self, Error>
    where
        R: std::io::Read,
    {
        use unsigned_varint::io::read_u64;

        let size = read_u64(&mut r)?;
        if size > S as u64 || size > u8::MAX as u64 {
            return Err(Error::InvalidSize(size));
        }
        let mut digest = [0; S];
        r.read_exact(&mut digest[..size as usize])?;
        Ok(Self::from(digest))
    }
}

/// Trait implemented by a hash function implementation.
pub trait StatefulHasher<const S: usize>: Default + Send + Sync {
    /// The Digest type to distinguish the output of different `Hasher` implementations.
    type Digest: Digest<S>;

    /// Consume input and update internal state.
    fn update(&mut self, input: &[u8]);

    /// Returns the final digest.
    fn finalize(&self) -> Self::Digest;

    /// Reset the internal hasher state.
    fn reset(&mut self);
}

/// Trait implemented by a hash function implementation.
///
/// It specifies its own Digest type, so that the output of the hash function can later be
/// distinguished. This way you can create a [`MultihashDigest`] from a `Digest`.
///
/// Every hashing algorithm that is used with Multihash needs to implement those. This trait is
/// very similar to the external [`digest::Digest` trait]. There is a small significant
/// difference, which needed the introduction of this `Hasher` trait instead of re-using the
/// widely used `digest::Digest` trait.
///
/// The external `digest::Digest` trait has a single return type called [`Output`], which is used
/// for all hashers that implement it. It's basically a wrapper around the hashed result bytes.
/// For Multihashes we need to distinguish those bytes, as we care about which hash function they
/// were created with (which is the whole point of [Multihashes]). Therefore the [`Hasher`] trait
/// defines an [associated type] [`Hasher::Digest`] for the output of the hasher. This way the
/// implementers can specify their own, hasher specific type (which implements [`Digest`]) for
/// their output.
///
/// [`digest::Digest` trait]: https://docs.rs/digest/0.9.0/digest/trait.Digest.html
/// [`Output`]: https://docs.rs/digest/0.9.0/digest/type.Output.html
/// [Multihashes]: https://github.com/multiformats/multihash
/// [associated type]: https://doc.rust-lang.org/book/ch19-03-advanced-traits.html#specifying-placeholder-types-in-trait-definitions-with-associated-types
/// [`MultihashDigest`]: crate::MultihashDigest
pub trait Hasher<const S: usize>: Default + Send + Sync {
    /// The Digest type to distinguish the output of different `Hasher` implementations.
    type Digest: Digest<S>;

    ///the allocated size of the digest.
    const SIZE: usize = S;

    /// Hashes the given `input` data and returns its hash digest.
    fn digest(input: &[u8]) -> Self::Digest
    where
        Self: Sized;
}

impl<T: StatefulHasher<S>, const S: usize> Hasher<S> for T {
    type Digest = T::Digest;

    fn digest(input: &[u8]) -> Self::Digest {
        let mut hasher = Self::default();
        hasher.update(input);
        hasher.finalize()
    }
}
