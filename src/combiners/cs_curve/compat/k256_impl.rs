// copied from cait-sith
use super::*;

use k256::elliptic_curve::bigint::Bounded;
use k256::Secp256k1;

impl CSCurve for Secp256k1 {
    const NAME: &'static [u8] = b"Secp256k1";
    const BITS: usize = <Self::Uint as Bounded>::BITS;

    fn serialize_point<S: Serializer>(
        point: &Self::AffinePoint,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        point.serialize(serializer)
    }

    fn deserialize_point<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Self::AffinePoint, D::Error> {
        Self::AffinePoint::deserialize(deserializer)
    }
}
