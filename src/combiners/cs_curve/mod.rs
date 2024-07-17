/// This code mod and the /compat is copied directly from the Lit Protocol cait-sith repo.
mod compat;

use compat::CSCurve;
use k256::elliptic_curve::subtle::ConditionallySelectable;
use k256::elliptic_curve::{ops::Invert, scalar::IsHigh, Field, Group};

/// Represents a signature with extra information, to support different variants of ECDSA.
///
/// An ECDSA signature is usually two scalars. The first scalar is derived from
/// a point on the curve, and because this process is lossy, some other variants
/// of ECDSA also include some extra information in order to recover this point.
///
/// Furthermore, some signature formats may disagree on how precisely to serialize
/// different values as bytes.
///
/// To support these variants, this simply gives you a normal signature, along with the entire
/// first point.
#[derive(Clone)]
pub struct FullSignature<C: CSCurve> {
    /// This is the entire first point.
    pub big_r: C::AffinePoint,
    /// This is the second scalar, normalized to be in the lower range.
    pub s: C::Scalar,
}

impl<C: CSCurve> FullSignature<C> {
    #[must_use]
    pub fn verify(&self, public_key: &C::AffinePoint, msg_hash: &C::Scalar) -> bool {
        let r: C::Scalar = compat::x_coordinate::<C>(&self.big_r);
        if r.is_zero().into() || self.s.is_zero().into() {
            return false;
        }
        let s_inv = self.s.invert_vartime().unwrap();
        let reproduced = (C::ProjectivePoint::generator() * (*msg_hash * s_inv))
            + (C::ProjectivePoint::from(*public_key) * (r * s_inv));
        compat::x_coordinate::<C>(&reproduced.into()) == r
    }
}

pub fn combine_signature_shares<C: CSCurve>(
    shares: Vec<C::Scalar>,
    public_key: C::AffinePoint,
    // presignature: PresignOutput<C>,
    presignature_big_r: C::AffinePoint,
    msg_hash: C::Scalar,
) -> Result<FullSignature<C>, &'static str> {
    let mut s: C::Scalar = shares[0];
    for &s_j in shares.iter().skip(1) {
        // s += C::Scalar::from(*s_j)
        s += s_j
    }

    // Spec 2.3
    // Optionally, normalize s
    s.conditional_assign(&(-s), s.is_high());
    let sig = FullSignature {
        big_r: presignature_big_r,
        s,
    };
    if !sig.verify(&public_key, &msg_hash) {
        return Err("signature failed to verify");
    }

    // Spec 2.4
    Ok(sig)
}
