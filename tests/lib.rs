use std::io::{Cursor, Write};

use multihash::{
    derive::Multihash, Blake2b256, Blake2b512, Blake2bDigest, Blake2s128, Blake2s256,
    Blake2sDigest, Blake3Digest, Blake3_256, Digest, Error, Hasher, Identity256, IdentityDigest,
    Keccak224, Keccak256, Keccak384, Keccak512, KeccakDigest, MultihashDigest, MultihashGeneric,
    Sha1, Sha1Digest, Sha2Digest, Sha2_256, Sha2_512, Sha3Digest, Sha3_224, Sha3_256, Sha3_384,
    Sha3_512, StatefulHasher, Strobe256, Strobe512, StrobeDigest,
};

#[derive(Clone, Copy, Debug, Eq, Multihash, PartialEq)]
#[mh(alloc_size = 64)]
pub enum Code {
    #[mh(code = 0x00, hasher = Identity256, digest = IdentityDigest<32>)]
    Identity,
    #[mh(code = 0x11, hasher = Sha1, digest = Sha1Digest<20>)]
    Sha1,
    #[mh(code = 0x12, hasher = Sha2_256, digest = Sha2Digest<32>)]
    Sha2_256,
    #[mh(code = 0x13, hasher = Sha2_512, digest = Sha2Digest<64>)]
    Sha2_512,
    #[mh(code = 0x17, hasher = Sha3_224, digest = Sha3Digest<28>)]
    Sha3_224,
    #[mh(code = 0x16, hasher = Sha3_256, digest = Sha3Digest<32>)]
    Sha3_256,
    #[mh(code = 0x15, hasher = Sha3_384, digest = Sha3Digest<48>)]
    Sha3_384,
    #[mh(code = 0x14, hasher = Sha3_512, digest = Sha3Digest<64>)]
    Sha3_512,
    #[mh(code = 0x1a, hasher = Keccak224, digest = KeccakDigest<28>)]
    Keccak224,
    #[mh(code = 0x1b, hasher = Keccak256, digest = KeccakDigest<32>)]
    Keccak256,
    #[mh(code = 0x1c, hasher = Keccak384, digest = KeccakDigest<48>)]
    Keccak384,
    #[mh(code = 0x1d, hasher = Keccak512, digest = KeccakDigest<64>)]
    Keccak512,
    #[mh(code = 0xb220, hasher = Blake2b256, digest = Blake2bDigest<32>)]
    Blake2b256,
    #[mh(code = 0xb240, hasher = Blake2b512, digest = Blake2bDigest<64>)]
    Blake2b512,
    #[mh(code = 0xb250, hasher = Blake2s128, digest = Blake2sDigest<16>)]
    Blake2s128,
    #[mh(code = 0xb260, hasher = Blake2s256, digest = Blake2sDigest<32>)]
    Blake2s256,
    #[mh(code = 0x1e, hasher = Blake3_256, digest = Blake3Digest<32>)]
    Blake3_256,
    #[mh(code = 0x3312e7, hasher = Strobe256, digest = StrobeDigest<16>)]
    Strobe256,
    #[mh(code = 0x3312e8, hasher = Strobe512, digest = StrobeDigest<32>)]
    Strobe512,
}

macro_rules! assert_encode {
   // Mutlihash enum member, Multihash code, input, Multihash as hex
   {$( $alg:ty, $code:expr, $data:expr, $expect:expr; )*} => {
       $(
           let expected = hex::decode($expect).unwrap();

           // From code
           assert_eq!(
               $code.digest($data).to_bytes(),
               expected,
               "{:?} encodes correctly (from code)", stringify!($alg)
           );

           // From digest
           assert_eq!(
             Code::multihash_from_digest(&<$alg>::digest($data)).to_bytes(),
             expected,
             "{:?} encodes correctly (from digest)", stringify!($alg)
           );

           // From incremental hashing
           let mut hasher = <$alg>::default();
           hasher.update($data);
           assert_eq!(
               Code::multihash_from_digest(&hasher.finalize()).to_bytes(),
               expected,
               "{:?} encodes correctly (from hasher)", stringify!($alg)
           );
       )*
   }
}

#[allow(clippy::cognitive_complexity)]
#[test]
fn multihash_encode() {
    assert_encode! {
        Identity256, Code::Identity, b"beep boop", "00096265657020626f6f70";
        Sha1, Code::Sha1, b"beep boop", "11147c8357577f51d4f0a8d393aa1aaafb28863d9421";
        Sha2_256, Code::Sha2_256, b"helloworld", "1220936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af";
        Sha2_256, Code::Sha2_256, b"beep boop", "122090ea688e275d580567325032492b597bc77221c62493e76330b85ddda191ef7c";
        Sha2_512, Code::Sha2_512, b"hello world", "1340309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f";
        Sha3_224, Code::Sha3_224, b"hello world", "171Cdfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5";
        Sha3_256, Code::Sha3_256, b"hello world", "1620644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938";
        Sha3_384, Code::Sha3_384, b"hello world", "153083bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b";
        Sha3_512, Code::Sha3_512, b"hello world", "1440840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a";
        Keccak224, Code::Keccak224, b"hello world", "1A1C25f3ecfebabe99686282f57f5c9e1f18244cfee2813d33f955aae568";
        Keccak256, Code::Keccak256, b"hello world", "1B2047173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad";
        Keccak384, Code::Keccak384, b"hello world", "1C3065fc99339a2a40e99d3c40d695b22f278853ca0f925cde4254bcae5e22ece47e6441f91b6568425adc9d95b0072eb49f";
        Keccak512, Code::Keccak512, b"hello world", "1D403ee2b40047b8060f68c67242175660f4174d0af5c01d47168ec20ed619b0b7c42181f40aa1046f39e2ef9efc6910782a998e0013d172458957957fac9405b67d";
        Blake2b512, Code::Blake2b512, b"hello world", "c0e40240021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0";
        Blake2s256, Code::Blake2s256, b"hello world", "e0e402209aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b";
        Blake2b256, Code::Blake2b256, b"hello world", "a0e40220256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610";
        Blake2s128, Code::Blake2s128, b"hello world", "d0e4021037deae0226c30da2ab424a7b8ee14e83";
        Blake3_256, Code::Blake3_256, b"hello world", "1e20d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24";
    }
}

macro_rules! assert_decode {
    {$( $code:expr, $hash:expr; )*} => {
        $(
            let hash = hex::decode($hash).unwrap();
            assert_eq!(
                Multihash::from_bytes(&hash).unwrap().code(),
                u64::from($code),
                "{:?} decodes correctly", stringify!($code)
            );
        )*
    }
}

#[test]
fn assert_decode() {
    assert_decode! {
        Code::Identity, "000a68656c6c6f776f726c64";
        Code::Sha1, "11147c8357577f51d4f0a8d393aa1aaafb28863d9421";
        Code::Sha2_256, "1220936a185caaa266bb9cbe981e9e05cb78cd732b0b3280eb944412bb6f8f8f07af";
        Code::Sha2_256, "122090ea688e275d580567325032492b597bc77221c62493e76330b85ddda191ef7c";
        Code::Sha2_512, "1340309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f";
        Code::Sha3_224, "171Cdfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5";
        Code::Sha3_256, "1620644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938";
        Code::Sha3_384, "153083bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b";
        Code::Sha3_512, "1440840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a";
        Code::Keccak224, "1A1C25f3ecfebabe99686282f57f5c9e1f18244cfee2813d33f955aae568";
        Code::Keccak256, "1B2047173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad";
        Code::Keccak384, "1C3065fc99339a2a40e99d3c40d695b22f278853ca0f925cde4254bcae5e22ece47e6441f91b6568425adc9d95b0072eb49f";
        Code::Keccak512, "1D403ee2b40047b8060f68c67242175660f4174d0af5c01d47168ec20ed619b0b7c42181f40aa1046f39e2ef9efc6910782a998e0013d172458957957fac9405b67d";
        Code::Blake2b512, "c0e40240021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0";
        Code::Blake2s256, "e0e402209aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b";
        Code::Blake2b256, "a0e40220256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610";
        Code::Blake2s128, "d0e4021037deae0226c30da2ab424a7b8ee14e83";
        Code::Blake3_256, "1e20d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24";
    }
}

macro_rules! assert_roundtrip {
    ($( $code:expr, $alg:ident; )*) => {
        $(
            // Hashing with one call
            {
                let hash = $code.digest(b"helloworld");
                assert_eq!(
                    Multihash::from_bytes(&hash.to_bytes()).unwrap().code(),
                    hash.code()
                );
            }
            // Hashing incrementally
            {
                let mut hasher = <$alg>::default();
                hasher.update(b"helloworld");
                let hash = Code::multihash_from_digest(&hasher.finalize());
                assert_eq!(
                    Multihash::from_bytes(&hash.to_bytes()).unwrap().code(),
                    hash.code()
                );
            }
            // Hashing as `Write` implementation
            {
                let mut hasher = <$alg>::default();
                hasher.write_all(b"helloworld").unwrap();
                let hash = Code::multihash_from_digest(&hasher.finalize());
                assert_eq!(
                    Multihash::from_bytes(&hash.to_bytes()).unwrap().code(),
                    hash.code()
                );
            }
        )*
    }
}

#[allow(clippy::cognitive_complexity)]
#[test]
fn assert_roundtrip() {
    assert_roundtrip!(
        Code::Identity, Identity256;
        Code::Sha1, Sha1;
        Code::Sha2_256, Sha2_256;
        Code::Sha2_512, Sha2_512;
        Code::Sha3_224, Sha3_224;
        Code::Sha3_256, Sha3_256;
        Code::Sha3_384, Sha3_384;
        Code::Sha3_512, Sha3_512;
        Code::Keccak224, Keccak224;
        Code::Keccak256, Keccak256;
        Code::Keccak384, Keccak384;
        Code::Keccak512, Keccak512;
        Code::Blake2b512, Blake2b512;
        Code::Blake2s256, Blake2s256;
        Code::Blake3_256, Blake3_256;
    );
}

/// Testing the public interface of `Multihash` and coversions to it
fn multihash_methods<H, const S: usize>(code: Code, prefix: &str, digest_str: &str)
where
    H: StatefulHasher<S>,
    Code: for<'a> From<&'a H::Digest>,
{
    let digest = hex::decode(digest_str).unwrap();
    let expected_bytes = hex::decode(&format!("{}{}", prefix, digest_str)).unwrap();
    let mut expected_cursor = Cursor::new(&expected_bytes);
    let multihash = code.digest(b"hello world");

    assert_eq!(Multihash::wrap(code.into(), &digest).unwrap(), multihash);
    assert_eq!(multihash.code(), u64::from(code));
    assert_eq!(multihash.size() as usize, digest.len());
    assert_eq!(multihash.digest(), digest);
    assert_eq!(Multihash::read(&mut expected_cursor).unwrap(), multihash);
    assert_eq!(Multihash::from_bytes(&expected_bytes).unwrap(), multihash);
    let mut written_buf = Vec::new();
    multihash.write(&mut written_buf).unwrap();
    assert_eq!(written_buf, expected_bytes);
    assert_eq!(multihash.to_bytes(), expected_bytes);

    // Test from hasher digest conversion
    let mut hasher = H::default();
    hasher.update(b"hello world");
    let multihash_from_digest = Code::multihash_from_digest(&hasher.finalize());
    assert_eq!(multihash_from_digest.code(), u64::from(code));
    assert_eq!(multihash_from_digest.size() as usize, digest.len());
    assert_eq!(multihash_from_digest.digest(), digest);
}

#[test]
fn test_multihash_methods() {
    multihash_methods::<Identity256, { Identity256::SIZE }>(
        Code::Identity,
        "000b",
        "68656c6c6f20776f726c64",
    );
    multihash_methods::<Sha1, { Sha1::SIZE }>(
        Code::Sha1,
        "1114",
        "2aae6c35c94fcfb415dbe95f408b9ce91ee846ed",
    );
    multihash_methods::<Sha2_256, { Sha2_256::SIZE }>(
        Code::Sha2_256,
        "1220",
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
    );
    multihash_methods::<Sha2_512, {Sha2_512::SIZE}>(
      Code::Sha2_512,
     "1340",
     "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f989dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f");
    multihash_methods::<Sha3_224, { Sha3_224::SIZE }>(
        Code::Sha3_224,
        "171C",
        "dfb7f18c77e928bb56faeb2da27291bd790bc1045cde45f3210bb6c5",
    );
    multihash_methods::<Sha3_256, { Sha3_256::SIZE }>(
        Code::Sha3_256,
        "1620",
        "644bcc7e564373040999aac89e7622f3ca71fba1d972fd94a31c3bfbf24e3938",
    );
    multihash_methods::<Sha3_384, {Sha3_384::SIZE}>(
     Code::Sha3_384,
     "1530",
     "83bff28dde1b1bf5810071c6643c08e5b05bdb836effd70b403ea8ea0a634dc4997eb1053aa3593f590f9c63630dd90b");
    multihash_methods::<Sha3_512, {Sha3_512::SIZE}>(
     Code::Sha3_512,
     "1440",
     "840006653e9ac9e95117a15c915caab81662918e925de9e004f774ff82d7079a40d4d27b1b372657c61d46d470304c88c788b3a4527ad074d1dccbee5dbaa99a");
    multihash_methods::<Keccak224, { Keccak224::SIZE }>(
        Code::Keccak224,
        "1A1C",
        "25f3ecfebabe99686282f57f5c9e1f18244cfee2813d33f955aae568",
    );
    multihash_methods::<Keccak256, { Keccak256::SIZE }>(
        Code::Keccak256,
        "1B20",
        "47173285a8d7341e5e972fc677286384f802f8ef42a5ec5f03bbfa254cb01fad",
    );
    multihash_methods::<Keccak384, {Keccak384::SIZE}>(
     Code::Keccak384,
     "1C30",
     "65fc99339a2a40e99d3c40d695b22f278853ca0f925cde4254bcae5e22ece47e6441f91b6568425adc9d95b0072eb49f");
    multihash_methods::<Keccak512, {Keccak512::SIZE}>(
     Code::Keccak512,
     "1D40",
     "3ee2b40047b8060f68c67242175660f4174d0af5c01d47168ec20ed619b0b7c42181f40aa1046f39e2ef9efc6910782a998e0013d172458957957fac9405b67d");
    multihash_methods::<Blake2b512, {Blake2b512::SIZE}>(
     Code::Blake2b512,
     "c0e40240",
     "021ced8799296ceca557832ab941a50b4a11f83478cf141f51f933f653ab9fbcc05a037cddbed06e309bf334942c4e58cdf1a46e237911ccd7fcf9787cbc7fd0");
    multihash_methods::<Blake2s256, { Blake2s256::SIZE }>(
        Code::Blake2s256,
        "e0e40220",
        "9aec6806794561107e594b1f6a8a6b0c92a0cba9acf5e5e93cca06f781813b0b",
    );
    multihash_methods::<Blake2b256, { Blake2b256::SIZE }>(
        Code::Blake2b256,
        "a0e40220",
        "256c83b297114d201b30179f3f0ef0cace9783622da5974326b436178aeef610",
    );
    multihash_methods::<Blake2s128, { Blake2s128::SIZE }>(
        Code::Blake2s128,
        "d0e40210",
        "37deae0226c30da2ab424a7b8ee14e83",
    );
    multihash_methods::<Blake3_256, { Blake3_256::SIZE }>(
        Code::Blake3_256,
        "1e20",
        "d74981efa70a0c880b8d8c1985d075dbcbf679b99a5f9914e5aaf96b831a9e24",
    );
}

#[test]
#[should_panic]
fn test_long_identity_hash() {
    // The identity hash panics if the input size is bigger than the maximum size
    let input = b"abcdefghijklmnopqrstuvwxyz abcdefghijklmnopqrstuvwxyz";
    Identity256::digest(input);
}

#[test]
fn multihash_errors() {
    assert!(
        Multihash::from_bytes(&[]).is_err(),
        "Should error on empty data"
    );
    assert!(
        Multihash::from_bytes(&[1, 2, 3]).is_err(),
        "Should error on invalid multihash"
    );
    assert!(
        Multihash::from_bytes(&[1, 2, 3]).is_err(),
        "Should error on invalid prefix"
    );
    assert!(
        Multihash::from_bytes(&[0x12, 0x20, 0xff]).is_err(),
        "Should error on correct prefix with wrong digest"
    );
    let identity_code: u8 = 0x00;
    let identity_length = 3;
    assert!(
        Multihash::from_bytes(&[identity_code, identity_length, 1, 2, 3, 4]).is_err(),
        "Should error on wrong hash length"
    );
}
