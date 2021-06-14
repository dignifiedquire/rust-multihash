use quickcheck::{Arbitrary, Gen};
use rand::{
    distributions::{weighted::WeightedIndex, Distribution},
    Rng,
};

use crate::MultihashGeneric;

/// Generates a random valid multihash.
impl Arbitrary for MultihashGeneric<64> {
    fn arbitrary<G: Gen>(g: &mut G) -> Self {
        // In real world lower multihash codes are more likely to happen, hence distribute them
        // with bias towards smaller values.
        let weights = [128, 64, 32, 16, 8, 4, 2, 1];
        let dist = WeightedIndex::new(weights.iter()).unwrap();
        let code = match dist.sample(g) {
            0 => g.gen_range(0, u64::pow(2, 7)),
            1 => g.gen_range(u64::pow(2, 7), u64::pow(2, 14)),
            2 => g.gen_range(u64::pow(2, 14), u64::pow(2, 21)),
            3 => g.gen_range(u64::pow(2, 21), u64::pow(2, 28)),
            4 => g.gen_range(u64::pow(2, 28), u64::pow(2, 35)),
            5 => g.gen_range(u64::pow(2, 35), u64::pow(2, 42)),
            6 => g.gen_range(u64::pow(2, 42), u64::pow(2, 49)),
            7 => g.gen_range(u64::pow(2, 56), u64::pow(2, 63)),
            _ => unreachable!(),
        };

        // Maximum size is 64 byte due to the `U64` generic
        let size = g.gen_range(0, 64);
        let mut data = [0; 64];
        g.fill_bytes(&mut data);
        MultihashGeneric::wrap(code, &data[..size]).unwrap()
    }
}
