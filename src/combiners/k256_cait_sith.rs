use crate::{
    errors::CombinationError,
    models::{SignatureRecidHex, SignedDatak256},
};

use super::cs_curve::combine_signature_shares;
use k256::elliptic_curve::{
    group::GroupEncoding, ops::Reduce, point::AffineCoordinates, sec1::ToEncodedPoint, Curve,
    CurveArithmetic,
};
use k256::{
    ecdsa::{RecoveryId, VerifyingKey},
    AffinePoint, Scalar, Secp256k1,
};

#[derive(Clone, PartialEq, Debug)]
pub struct SignatureRecid {
    pub r: AffinePoint,
    pub s: Scalar,
    pub recid: u8,
}

#[doc = "Entry point for recombining signatures."]
pub fn combine_signature(shares: Vec<String>) -> String {
    let sig = combine_signature_internal(shares);
    let sig = match sig {
        Ok(s) => s,
        Err(e) => return e.to_string(),
    };
    let sig_hex = SignatureRecidHex {
        r: hex::encode(sig.r.to_bytes()),
        s: hex::encode(sig.s.to_bytes()),
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
            return Err(CombinationError::DeserializeError(format!(
                "Unable to deserialize '{}' - {:?}",
                share, data
            )));
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

    Ok(sig)
}

#[doc = "Basic math required to agregate signature shares and generate the final sig."]
pub fn do_combine_signature(
    public_key: AffinePoint,
    presignature_big_r: AffinePoint,
    msg_hash: Scalar,
    shares: Vec<Scalar>,
) -> SignatureRecid {
    let sig =
        combine_signature_shares::<Secp256k1>(shares, public_key, presignature_big_r, msg_hash);

    let sig = sig.unwrap();

    let r = sig.big_r;
    let s = sig.s;

    let signature = k256::ecdsa::Signature::from_scalars(
        <<Secp256k1 as CurveArithmetic>::Scalar as Reduce<<Secp256k1 as Curve>::Uint>>::reduce_bytes(&r.x()),
        s,
    ).expect("Couldn't create signature");
    // Convert our signature into a recoverable one
    let pubkey_0 = VerifyingKey::recover_from_prehash(
        &msg_hash.to_bytes(),
        &signature,
        RecoveryId::try_from(0).expect("Couldn't create recovery id"),
    )
    .expect("Couldn't recover pubkey for recovery id : 0");
    let pubkey_1 = VerifyingKey::recover_from_prehash(
        &msg_hash.to_bytes(),
        &signature,
        RecoveryId::try_from(1).expect("Couldn't create recovery id"),
    )
    .expect("Couldn't recover pubkey for recovery id : 1");

    let recid = if pubkey_0.to_encoded_point(false) == public_key.to_encoded_point(false) {
        0
    } else if pubkey_1.to_encoded_point(false) == public_key.to_encoded_point(false) {
        1
    } else {
        panic!("Neither recovery ID leads to the correct public key");
    };
    SignatureRecid { r, s, recid }
}
