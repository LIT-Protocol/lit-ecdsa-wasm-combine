use crate::{
    errors::CombinationError,
    models::{SignatureRecidHex, SignedDatak256},
};

use super::cs_curve::{combine_signature_shares, FullSignature};
use elliptic_curve::{
    bigint, group::GroupEncoding, ops::Reduce, point::AffineCoordinates, subtle::ConstantTimeLess,
    Curve, CurveArithmetic,
};
use k256::{
    ecdsa::{RecoveryId, Signature as EcdsaSignature, VerifyingKey},
    AffinePoint, Scalar, Secp256k1,
};

#[derive(Clone, PartialEq, Debug)]
struct Signature {
    pub r: Scalar,
    pub s: Scalar,
}

#[derive(Clone, PartialEq, Debug)]
pub struct SignatureRecid {
    pub r: AffinePoint,
    pub s: Scalar,
    pub recid: u8,
}

#[doc = "Entry point for recombining signatures."]
pub fn combine_signature(shares: Vec<String>) -> String {
    let sig = combine_signature_internal(shares);
    if sig.is_err() {
        return sig.unwrap_err().to_string();
    }

    let sig = sig.unwrap();
    let sig_hex = SignatureRecidHex {
        r: hex::encode(&sig.r.to_bytes()),
        s: hex::encode(&sig.s.to_bytes()),
        recid: sig.recid,
    };

    serde_json::to_string(&sig_hex).unwrap()
}

#[doc = "Entry point for recombining signatures."]
fn combine_signature_internal(shares: Vec<String>) -> Result<SignatureRecid, CombinationError> {
    let mut signed_data: Vec<SignedDatak256> = Vec::new();
    for share in shares {
        let data = serde_json::from_str(&share);
        if data.is_err() {
            return Err(CombinationError::DeserializeError);
        }
        signed_data.push(data.unwrap());
    }

    let public_key = signed_data[0].public_key;
    let msg_hash = signed_data[0].data_signed;
    let presignature_big_r = signed_data[0].big_r;

    let shares = signed_data
        .iter()
        .map(|x| x.signature_share)
        .collect::<Vec<Scalar>>();

    let sig = do_combine_signature(public_key, presignature_big_r, msg_hash, shares);

    println!("sig: {:?}", &sig);

    sig
}

#[doc = "Basic math required to aggregate signature shares and generate the final sig."]
fn do_combine_signature(
    public_key: AffinePoint,
    presignature_big_r: AffinePoint,
    msg_hash: Scalar,
    shares: Vec<Scalar>,
) -> Result<SignatureRecid, CombinationError> {
    let sig =
        combine_signature_shares::<Secp256k1>(shares, public_key, presignature_big_r, msg_hash);
    let sig = sig.expect("Couldn't create signature");
    let msg = msg_hash.to_bytes();
    let r = <<Secp256k1 as CurveArithmetic>::Scalar as Reduce<<Secp256k1 as Curve>::Uint>>::reduce_bytes(&sig.big_r.x());
    let ecdsa_sig = EcdsaSignature::from_scalars(r, sig.s).expect("Couldn't create signature");
    let vk = VerifyingKey::from_affine(public_key).expect("Couldn't create vk");
    let recid = RecoveryId::trial_recovery_from_prehash(&vk, &msg, &ecdsa_sig)
        .map_err(|_| CombinationError::DeserializeError)?;

    Ok(SignatureRecid {
        r: sig.big_r,
        s: sig.s,
        recid: recid.to_byte(),
    })
}

// #[doc = "Basic math required to agregate signature shares and generate the final sig."]
// pub fn do_combine_signature(
//     public_key: AffinePoint,
//     presignature_big_r: AffinePoint,
//     msg_hash: Scalar,
//     shares: Vec<Scalar>,
// ) -> SignatureRecid {
//     let sig =
//         combine_signature_shares::<Secp256k1>(shares, public_key, presignature_big_r, msg_hash);

//     let sig = sig.unwrap();

//     let r = sig.big_r;
//     let s = sig.s;

//     // calc the recovery id
//     use elliptic_curve::point::AffineCoordinates;
//     use elliptic_curve::Curve;
//     let mut recid  =  if presignature_big_r.y_is_odd().into() { 1 } else { 0 };
//     // let s_bi = num_bigint::BigUint::from_bytes_be( &s.to_bytes());
//     // let order = num_bigint::BigUint::from_bytes_be( &k256::Secp256k1::ORDER.to_be_bytes());

//     // if s_bi > order - &s_bi {
//     //     recid ^= 1;
//     // }

//     SignatureRecid { r, s, recid }
// }

// SIMPLIFIED
// #[doc = "Basic math required to agregate signature shares and generate the final sig."]
// pub fn do_combine_signature(
//     public_key: AffinePoint,
//     presignature_big_r: AffinePoint,
//     msg_hash: Scalar,
//     shares: Vec<Scalar>,
// ) -> SignatureRecid {
//     let sig =
//         combine_signature_shares::<Secp256k1>(shares, public_key, presignature_big_r, msg_hash);

//     let sig = sig.unwrap();
//     let r = sig.big_r;
//     let s = sig.s;
//     // s is always low, so we have a simplified rec id calc of 1 or 0.
//     let recid  =  if presignature_big_r.y_is_odd().into() { 0 } else { 1 };

//     SignatureRecid { r, s, recid }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use elliptic_curve::Field;
    use k256::ProjectivePoint;
    use rand::prelude::SliceRandom;
    use vsss_rs::{
        elliptic_curve::PrimeField, shamir, DefaultShare, IdentifierPrimeField, Share,
        ShareIdentifier,
    };

    #[test]
    fn combine_test() {
        const THRESHOLD: usize = 6;
        const SIGNERS: usize = 10;
        const REPS: usize = 50;
        const MSG: &[u8] = b"\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0combine test";
        type SecretShares =
            DefaultShare<IdentifierPrimeField<Scalar>, IdentifierPrimeField<Scalar>>;
        let z = Scalar::from_repr(<Scalar as PrimeField>::Repr::clone_from_slice(MSG)).unwrap();

        let mut rng = rand::thread_rng();

        for i in 0..REPS {
            let sk = k256::ecdsa::SigningKey::random(&mut rng);
            let pk = k256::ecdsa::VerifyingKey::from(&sk);

            let sk_scalar: &Scalar = sk.as_nonzero_scalar().as_ref();
            let secret = IdentifierPrimeField(*sk_scalar);
            let mut shares =
                shamir::split_secret::<SecretShares>(THRESHOLD, SIGNERS, &secret, &mut rng)
                    .unwrap();

            let k = Scalar::random(&mut rng);
            let k_inv = k.invert().unwrap();
            let big_r = ProjectivePoint::GENERATOR * k;
            let big_r = big_r.to_affine();
            let r = <<Secp256k1 as CurveArithmetic>::Scalar as Reduce<
                <Secp256k1 as Curve>::Uint,
            >>::reduce_bytes(&big_r.x());

            shares.shuffle(&mut rng);
            let mut sig_shares = Vec::with_capacity(THRESHOLD);
            let ids = shares
                .iter()
                .take(THRESHOLD)
                .map(|s| s.identifier.0)
                .collect::<Vec<_>>();
            for signing_share in shares.iter().take(THRESHOLD) {
                let sig_share = k_inv
                    * (z + signing_share.value.0 * r)
                    * lagrange(&signing_share.identifier.0, &ids);
                sig_shares.push(sig_share);
            }

            let sig = do_combine_signature(*pk.as_affine(), big_r, z, sig_shares).unwrap();
            let signature = EcdsaSignature::from_scalars(r, sig.s).unwrap();
            let recid = RecoveryId::trial_recovery_from_prehash(&pk, MSG, &signature).unwrap();
            assert_eq!(
                recid.to_byte(),
                sig.recid,
                "failed at iteration {}, expected {}, found {}",
                i,
                recid.to_byte(),
                sig.recid
            );
        }
    }

    fn lagrange(xi: &Scalar, participants: &[Scalar]) -> Scalar {
        let xi = *(xi.as_ref());
        let mut num = Scalar::ONE;
        let mut den = Scalar::ONE;
        for xj in participants {
            let xj = *(xj.as_ref());
            if xi == xj {
                continue;
            }
            num *= xj;
            den *= xj - xi;
        }
        num * den.invert().expect("Denominator should not be zero")
    }
}
