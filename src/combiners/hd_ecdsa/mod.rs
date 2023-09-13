use error::Error;
// use web_sys::console;

use std::fmt::Debug;

use k256::elliptic_curve::group::cofactor::CofactorGroup;
use k256::elliptic_curve::hash2curve::{ExpandMsgXmd, FromOkm};
use k256::elliptic_curve::{
    hash2curve::GroupDigest, CurveArithmetic, Field, Group, ScalarPrimitive,
};

mod error;
pub const CXT: &[u8] = b"LIT_HD_KEY_ID_K256_XMD:SHA-256_SSWU_RO_NUL_";

pub fn hash_to_scalar<C>(id: &[u8], cxt: &[u8]) -> Result<C::Scalar, Error>
where
    C: GroupDigest,
    <C as CurveArithmetic>::ProjectivePoint: CofactorGroup,
    <C as CurveArithmetic>::Scalar: FromOkm,
{
    let scalar = C::hash_to_scalar::<ExpandMsgXmd<sha2::Sha256>>(&[id], &[cxt])?;
    Ok(scalar)
}

#[derive(Debug, Clone, Copy, Hash, Ord, PartialOrd, Eq, PartialEq, Deserialize, Serialize)]
pub struct HdKeyDeriver<C>(C::Scalar)
where
    C: GroupDigest,
    <C as CurveArithmetic>::ProjectivePoint: CofactorGroup,
    <C as CurveArithmetic>::Scalar: FromOkm;

impl<C> HdKeyDeriver<C>
where
    C: GroupDigest,
    <C as CurveArithmetic>::ProjectivePoint: CofactorGroup,
    <C as CurveArithmetic>::Scalar: FromOkm,
{
    pub fn new(id: &[u8], cxt: &[u8]) -> Result<Self, Error> {
        Ok(Self(hash_to_scalar::<C>(id, cxt)?))
    }

    pub fn compute_public_key(&self, public_keys: &[C::ProjectivePoint]) -> C::ProjectivePoint {
        let mut powers = vec![<C::Scalar as Field>::ONE; public_keys.len()];
        powers[1] = self.0;
        for i in 2..powers.len() {
            powers[i] = powers[i - 1] * self.0;
            //console::log_1(&js_sys::JsString::from(format!("power at index: {} value: {:?}", i, powers[i])));
        }
        sum_of_products_pippenger::<C>(public_keys, &powers)
    }
}

fn sum_of_products_pippenger<C: CurveArithmetic>(
    points: &[C::ProjectivePoint],
    scalars: &[C::Scalar],
) -> C::ProjectivePoint {
    const WINDOW: usize = 4;
    const NUM_BUCKETS: usize = 1 << WINDOW;
    const EDGE: usize = WINDOW - 1;
    const MASK: u64 = (NUM_BUCKETS - 1) as u64;

    let scalars = convert_scalars::<C>(scalars);
    let num_components = std::cmp::min(points.len(), scalars.len());
    let mut buckets = [<C::ProjectivePoint as Group>::identity(); NUM_BUCKETS];
    let mut res = C::ProjectivePoint::identity();
    let mut num_doubles = 0;
    let mut bit_sequence_index = 255usize;

    loop {
        for _ in 0..num_doubles {
            res = res.double();
        }

        let mut max_bucket = 0;
        let word_index = bit_sequence_index >> 6;
        let bit_index = bit_sequence_index & 63;

        if bit_index < EDGE {
            // we are on the edge of a word; have to look at the previous word, if it exists
            if word_index == 0 {
                // there is no word before
                let smaller_mask = ((1 << (bit_index + 1)) - 1) as u64;
                for i in 0..num_components {
                    let bucket_index: usize = (scalars[i][word_index] & smaller_mask) as usize;
                    if bucket_index > 0 {
                        buckets[bucket_index] += points[i];
                        if bucket_index > max_bucket {
                            max_bucket = bucket_index;
                        }
                    }
                }
            } else {
                // there is a word before
                let high_order_mask = ((1 << (bit_index + 1)) - 1) as u64;
                let high_order_shift = EDGE - bit_index;
                let low_order_mask = ((1 << high_order_shift) - 1) as u64;
                let low_order_shift = 64 - high_order_shift;
                let prev_word_index = word_index - 1;
                for i in 0..num_components {
                    let mut bucket_index =
                        ((scalars[i][word_index] & high_order_mask) << high_order_shift) as usize;
                    bucket_index |= ((scalars[i][prev_word_index] >> low_order_shift)
                        & low_order_mask) as usize;
                    if bucket_index > 0 {
                        buckets[bucket_index] += points[i];
                        if bucket_index > max_bucket {
                            max_bucket = bucket_index;
                        }
                    }
                }
            }
        } else {
            let shift = bit_index - EDGE;
            for i in 0..num_components {
                let bucket_index: usize = ((scalars[i][word_index] >> shift) & MASK) as usize;
                if bucket_index > 0 {
                    buckets[bucket_index] += points[i];
                    if bucket_index > max_bucket {
                        max_bucket = bucket_index;
                    }
                }
            }
        }
        res += &buckets[max_bucket];
        for i in (1..max_bucket).rev() {
            buckets[i] += buckets[i + 1];
            res += buckets[i];
            buckets[i + 1] = C::ProjectivePoint::identity();
        }
        buckets[1] = C::ProjectivePoint::identity();
        if bit_sequence_index < WINDOW {
            break;
        }
        bit_sequence_index -= WINDOW;
        num_doubles = {
            if bit_sequence_index < EDGE {
                bit_sequence_index + 1
            } else {
                WINDOW
            }
        };
    }
    res
}

#[cfg(target_pointer_width = "32")]
fn convert_scalars<C: CurveArithmetic>(scalars: &[C::Scalar]) -> Vec<[u64; 4]> {
    scalars
        .iter()
        .map(|s| {
            let mut out = [0u64; 4];
            let primitive: ScalarPrimitive<C> = (*s).into();
            let small_limbs = primitive
                .as_limbs()
                .iter()
                .map(|l| l.0 as u64)
                .collect::<Vec<_>>();
            let mut i = 0;
            let mut j = 0;
            while i < small_limbs.len() && j < out.len() {
                out[j] = small_limbs[i + 1] << 32 | small_limbs[i];
                i += 2;
                j += 1;
            }
            out
        })
        .collect::<Vec<_>>()
}

#[cfg(target_pointer_width = "64")]
fn convert_scalars<C: CurveArithmetic>(scalars: &[C::Scalar]) -> Vec<[u64; 4]> {
    scalars
        .iter()
        .map(|s| {
            let mut out = [0u64; 4];
            let primitive: ScalarPrimitive<C> = (*s).into();
            out.copy_from_slice(
                primitive
                    .as_limbs()
                    .iter()
                    .map(|l| l.0 as u64)
                    .collect::<Vec<_>>()
                    .as_slice(),
            );
            out
        })
        .collect::<Vec<_>>()
}
