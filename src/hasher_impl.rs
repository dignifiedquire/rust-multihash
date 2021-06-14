use crate::error::Error;
use crate::hasher::{Digest, StatefulHasher};
use core::convert::TryFrom;

macro_rules! derive_digest {
    ($name:ident) => {
        /// Multihash digest.
        #[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
        pub struct $name<const S: usize>([u8; S]);

        impl<const S: usize> Default for $name<S> {
            fn default() -> Self {
                [0u8; S].into()
            }
        }

        impl<const S: usize> AsRef<[u8]> for $name<S> {
            fn as_ref(&self) -> &[u8] {
                &self.0
            }
        }

        impl<const S: usize> AsMut<[u8]> for $name<S> {
            fn as_mut(&mut self) -> &mut [u8] {
                &mut self.0
            }
        }

        impl<const S: usize> From<[u8; S]> for $name<S> {
            fn from(array: [u8; S]) -> Self {
                Self(array)
            }
        }

        impl<const S: usize> From<$name<S>> for [u8; S] {
            fn from(digest: $name<S>) -> Self {
                digest.0
            }
        }

        /// Convert slice to `Digest`.
        ///
        /// It errors when the length of the slice does not match the size of the `Digest`.
        impl<const S: usize> TryFrom<&[u8]> for $name<S> {
            type Error = Error;

            fn try_from(slice: &[u8]) -> Result<Self, Self::Error> {
                Self::wrap(slice)
            }
        }

        impl<const S: usize> Digest<S> for $name<S> {}
    };
}

macro_rules! derive_write {
    ($name:ident) => {
        #[cfg(feature = "std")]
        impl<const S: usize> std::io::Write for $name<S> {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.update(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
    };
}

#[cfg(any(feature = "blake2b", feature = "blake2s"))]
macro_rules! derive_hasher_blake {
    ($module:ident, $name:ident, $digest:ident) => {
        derive_digest!($digest);

        /// Multihash hasher.
        #[derive(Debug)]
        pub struct $name<const S: usize> {
            state: $module::State,
        }

        impl<const S: usize> Default for $name<S> {
            fn default() -> Self {
                let mut params = $module::Params::new();
                params.hash_length(S);
                Self {
                    state: params.to_state(),
                }
            }
        }

        impl<const S: usize> StatefulHasher<S> for $name<S> {
            type Digest = $digest<S>;

            fn update(&mut self, input: &[u8]) {
                self.state.update(input);
            }

            fn finalize(&self) -> Self::Digest {
                let digest = self.state.finalize();
                let mut array = [0; S];
                array.clone_from_slice(digest.as_bytes());
                array.into()
            }

            fn reset(&mut self) {
                let Self { state, .. } = Self::default();
                self.state = state;
            }
        }

        derive_write!($name);
    };
}

#[cfg(feature = "blake2b")]
pub mod blake2b {
    use super::*;

    derive_hasher_blake!(blake2b_simd, Blake2bHasher, Blake2bDigest);

    /// 256 bit blake2b hasher.
    pub type Blake2b256 = Blake2bHasher<32>;

    /// 512 bit blake2b hasher.
    pub type Blake2b512 = Blake2bHasher<64>;
}

#[cfg(feature = "blake2s")]
pub mod blake2s {
    use super::*;

    derive_hasher_blake!(blake2s_simd, Blake2sHasher, Blake2sDigest);

    /// 256 bit blake2b hasher.
    pub type Blake2s128 = Blake2sHasher<16>;

    /// 512 bit blake2b hasher.
    pub type Blake2s256 = Blake2sHasher<32>;
}

#[cfg(feature = "blake3")]
pub mod blake3 {
    use super::*;

    // derive_hasher_blake!(blake3, Blake3Hasher, Blake3Digest);
    derive_digest!(Blake3Digest);

    /// Multihash hasher.
    #[derive(Debug)]
    pub struct Blake3Hasher<const S: usize> {
        hasher: ::blake3::Hasher,
    }

    impl<const S: usize> Default for Blake3Hasher<S> {
        fn default() -> Self {
            let hasher = ::blake3::Hasher::new();

            Self { hasher }
        }
    }

    impl<const S: usize> StatefulHasher<S> for Blake3Hasher<S> {
        type Digest = Blake3Digest<S>;

        fn update(&mut self, input: &[u8]) {
            self.hasher.update(input);
        }

        fn finalize(&self) -> Self::Digest {
            let digest = self.hasher.finalize(); //default is 32 bytes anyway
            let mut array = [0; S];
            array.clone_from_slice(digest.as_bytes());
            array.into()
        }

        fn reset(&mut self) {
            self.hasher.reset();
        }
    }

    derive_write!(Blake3Hasher);

    /// blake3-256 hasher.
    pub type Blake3_256 = Blake3Hasher<32>;
}

#[cfg(feature = "digest")]
macro_rules! derive_hasher_sha {
    ($module:ty, $name:ident, $size:expr, $digest:ident) => {
        /// Multihash hasher.
        #[derive(Debug, Default)]
        pub struct $name {
            state: $module,
        }

        impl $crate::hasher::StatefulHasher<$size> for $name {
            type Digest = $digest<$size>;

            fn update(&mut self, input: &[u8]) {
                use digest::Digest;
                self.state.update(input)
            }

            fn finalize(&self) -> Self::Digest {
                use digest::Digest;
                let digest = self.state.clone().finalize();
                let mut array = [0; $size];
                array.copy_from_slice(digest.as_slice());
                array.into()
            }

            fn reset(&mut self) {
                use digest::Digest;
                self.state.reset();
            }
        }

        #[cfg(feature = "std")]
        impl std::io::Write for $name {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.update(buf);
                Ok(buf.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
    };
}

#[cfg(feature = "sha1")]
pub mod sha1 {
    use super::*;

    derive_digest!(Sha1Digest);
    derive_hasher_sha!(::sha1::Sha1, Sha1, 20, Sha1Digest);
}

#[cfg(feature = "sha2")]
pub mod sha2 {
    use super::*;

    derive_digest!(Sha2Digest);
    derive_hasher_sha!(sha_2::Sha256, Sha2_256, 32, Sha2Digest);
    derive_hasher_sha!(sha_2::Sha512, Sha2_512, 64, Sha2Digest);
}

#[cfg(feature = "sha3")]
pub mod sha3 {
    use super::*;

    derive_digest!(Sha3Digest);
    derive_hasher_sha!(sha_3::Sha3_224, Sha3_224, 28, Sha3Digest);
    derive_hasher_sha!(sha_3::Sha3_256, Sha3_256, 32, Sha3Digest);
    derive_hasher_sha!(sha_3::Sha3_384, Sha3_384, 48, Sha3Digest);
    derive_hasher_sha!(sha_3::Sha3_512, Sha3_512, 64, Sha3Digest);

    derive_digest!(KeccakDigest);
    derive_hasher_sha!(sha_3::Keccak224, Keccak224, 28, KeccakDigest);
    derive_hasher_sha!(sha_3::Keccak256, Keccak256, 32, KeccakDigest);
    derive_hasher_sha!(sha_3::Keccak384, Keccak384, 48, KeccakDigest);
    derive_hasher_sha!(sha_3::Keccak512, Keccak512, 64, KeccakDigest);
}

pub mod identity {
    use super::*;
    use crate::error::Error;

    /// Multihash digest.
    #[derive(Clone, Debug, Eq, Hash, PartialEq)]
    pub struct IdentityDigest<const S: usize>(usize, [u8; S]);

    impl<const S: usize> Default for IdentityDigest<S> {
        fn default() -> Self {
            Self { 0: 0, 1: [0u8; S] }
        }
    }

    impl<const S: usize> AsRef<[u8]> for IdentityDigest<S> {
        fn as_ref(&self) -> &[u8] {
            &self.1[..self.0 as usize]
        }
    }

    impl<const S: usize> AsMut<[u8]> for IdentityDigest<S> {
        fn as_mut(&mut self) -> &mut [u8] {
            &mut self.1[..self.0 as usize]
        }
    }

    impl<const S: usize> From<[u8; S]> for IdentityDigest<S> {
        fn from(array: [u8; S]) -> Self {
            Self(array.len(), array)
        }
    }

    impl<const S: usize> From<IdentityDigest<S>> for [u8; S] {
        fn from(digest: IdentityDigest<S>) -> Self {
            digest.1
        }
    }

    impl<const S: usize> Digest<S> for IdentityDigest<S> {
        const SIZE: usize = S;

        // A custom implementation is needed as an identity hash value might be shorter than the
        // allocated Digest.
        fn wrap(digest: &[u8]) -> Result<Self, Error> {
            if digest.len() > S {
                return Err(Error::InvalidSize(digest.len() as _));
            }
            let mut array = [0; S];
            let len = digest.len().min(array.len());
            array[..len].copy_from_slice(&digest[..len]);
            Ok(Self(len, array))
        }

        // A custom implementation is needed as an identity hash also stores the actual size of
        // the given digest.
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
            Ok(Self(size as usize, digest))
        }
    }

    /// Identity hasher with a maximum size.
    ///
    /// # Panics
    ///
    /// Panics if the input is bigger than the maximum size.
    #[derive(Debug)]
    pub struct IdentityHasher<const S: usize> {
        bytes: [u8; S],
        i: usize,
    }

    impl<const S: usize> Default for IdentityHasher<S> {
        fn default() -> Self {
            Self {
                i: 0,
                bytes: [0u8; S],
            }
        }
    }

    impl<const S: usize> StatefulHasher<S> for IdentityHasher<S> {
        type Digest = IdentityDigest<S>;

        fn update(&mut self, input: &[u8]) {
            let start = self.i.min(self.bytes.len());
            let end = (self.i + input.len()).min(self.bytes.len());
            self.bytes[start..end].copy_from_slice(&input);
            self.i = end;
        }

        fn finalize(&self) -> Self::Digest {
            IdentityDigest(self.i, self.bytes)
        }

        fn reset(&mut self) {
            self.bytes = [0; S];
            self.i = 0;
        }
    }

    derive_write!(IdentityHasher);

    /// 32 byte Identity hasher (constrained to 32 bytes).
    ///
    /// # Panics
    ///
    /// Panics if the input is bigger than 32 bytes.
    pub type Identity256 = IdentityHasher<32>;
}

pub mod unknown {
    use super::*;
    derive_digest!(UnknownDigest);
}

#[cfg(feature = "strobe")]
pub mod strobe {
    use super::*;
    use strobe_rs::{SecParam, Strobe};

    derive_digest!(StrobeDigest);

    /// Strobe hasher.
    pub struct StrobeHasher<const S: usize> {
        strobe: Strobe,
        initialized: bool,
    }

    impl<const S: usize> Default for StrobeHasher<S> {
        fn default() -> Self {
            Self {
                strobe: Strobe::new(b"StrobeHash", SecParam::B128),
                initialized: false,
            }
        }
    }

    impl<const S: usize> StatefulHasher<S> for StrobeHasher<S> {
        type Digest = StrobeDigest<S>;

        fn update(&mut self, input: &[u8]) {
            self.strobe.ad(input, self.initialized);
            self.initialized = true;
        }

        fn finalize(&self) -> Self::Digest {
            let mut hash = [0; S];
            self.strobe.clone().prf(&mut hash, false);
            Self::Digest::from(hash)
        }

        fn reset(&mut self) {
            let Self { strobe, .. } = Self::default();
            self.strobe = strobe;
            self.initialized = false;
        }
    }

    derive_write!(StrobeHasher);

    /// 256 bit strobe hasher.
    pub type Strobe256 = StrobeHasher<32>;

    /// 512 bit strobe hasher.
    pub type Strobe512 = StrobeHasher<64>;
}
