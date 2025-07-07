use crate::{
    errors::CombinationError,
    models::{SignatureRecidHex, SignedDatak256},
};

use super::cs_curve::{combine_signature_shares, FullSignature};
use elliptic_curve::{bigint, group::GroupEncoding, ops::Reduce, point::AffineCoordinates, Curve, CurveArithmetic, subtle::ConstantTimeLess};
use k256::{
    ecdsa::{RecoveryId, VerifyingKey, Signature as EcdsaSignature},
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
    const N: bigint::U256 = bigint::U256::from_be_hex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141");

    let sig =
        combine_signature_shares::<Secp256k1>(shares, public_key, presignature_big_r, msg_hash);

    let sig = sig.expect("Couldn't create signature");

    let r_non_reduced = bigint::U256::from_be_slice(&sig.big_r.x());
    let is_x_reduced = (!r_non_reduced.ct_lt(&N)).unwrap_u8();
    let y_is_odd = sig.big_r.y_is_odd().unwrap_u8();
    debug_assert!(assert_recovery_id_is_correct(public_key, msg_hash, &sig, is_x_reduced, y_is_odd));

    Ok(SignatureRecid { r: sig.big_r, s: sig.s, recid: (is_x_reduced << 1) | y_is_odd })
}

fn assert_recovery_id_is_correct(
    public_key: AffinePoint,
    msg_hash: Scalar,
    sig: &FullSignature<Secp256k1>,
    is_x_reduced: u8,
    y_is_odd: u8,
) -> bool {
    let recid = RecoveryId::from_byte(is_x_reduced << 1 | y_is_odd).expect("a correct recovery id");
    let msg = msg_hash.to_bytes();
    let r = <<Secp256k1 as CurveArithmetic>::Scalar as Reduce<<Secp256k1 as Curve>::Uint>>::reduce_bytes(&sig.big_r.x());
    let ecdsa_sig = EcdsaSignature::from_scalars(r, sig.s).expect("Couldn't create signature");
    if let Ok(vk) = VerifyingKey::recover_from_prehash(msg.as_slice(), &ecdsa_sig, recid) {
        return *(vk.as_affine()) == public_key;
    }
    false
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
