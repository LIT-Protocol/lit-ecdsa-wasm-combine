use crate::{models::{SignatureRecidHex, SignedDatak256}, errors::CombinationError};

use super::cs_curve::combine_signature_shares;
use elliptic_curve::{group::GroupEncoding, bigint:: Encoding };
use k256::{AffinePoint, Scalar, Secp256k1};

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

    // calc the recovery id
    use elliptic_curve::point::AffineCoordinates;
    use elliptic_curve::Curve;
    let mut recid  =  if presignature_big_r.y_is_odd().into() { 1 } else { 0 };    
    let s_bi = num_bigint::BigUint::from_bytes_be( &s.to_bytes());
    let order = num_bigint::BigUint::from_bytes_be( &k256::Secp256k1::ORDER.to_be_bytes());

    if s_bi > order - &s_bi {
        recid ^= 1;
    }

    SignatureRecid { r, s, recid }
}
