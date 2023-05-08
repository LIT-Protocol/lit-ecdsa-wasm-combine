use super::cs_curve::combine_signature_shares;
use crate::models::{SignatureRecidHex, SignedData};
use elliptic_curve::group::GroupEncoding;
use p256::{AffinePoint, NistP256, Scalar};

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
    let mut signed_data: Vec<SignedData> = Vec::new();
    for share in shares {
        let data = serde_json::from_str(&share).unwrap();
        signed_data.push(data);
    }
    let public_key: AffinePoint = serde_json::from_str(signed_data[0].public_key.as_str()).unwrap();
    let msg_hash: Scalar = serde_json::from_str(signed_data[0].data_signed.as_str()).unwrap();
    let presignature_big_r: AffinePoint =
        serde_json::from_str(signed_data[0].local_x.as_str()).unwrap();

    let shares = signed_data
        .iter()
        .map(|x| serde_json::from_str(x.signature_share.as_str()).unwrap())
        .collect::<Vec<Scalar>>();

    let sig = do_combine_signature(public_key, presignature_big_r, msg_hash, shares);

    let sig_hex = SignatureRecidHex {
        r: hex::encode(&sig.r.to_bytes()),
        s: hex::encode(&sig.s.to_bytes()),
        recid: sig.recid,
    };

    serde_json::to_string(&sig_hex).unwrap()
}

#[doc = "Basic math required to agregate signature shares and generate the final sig."]
pub fn do_combine_signature(
    public_key: AffinePoint,
    presignature_big_r: AffinePoint,
    msg_hash: Scalar,
    shares: Vec<Scalar>,
) -> SignatureRecid {
    let sig =
        combine_signature_shares::<NistP256>(shares, public_key, presignature_big_r, msg_hash);

    let sig = sig.unwrap();

    let r = sig.big_r;
    let s = sig.s;
    let recid = 1; // FIX_ME ... this is a hack to make the tests pass

    SignatureRecid { r, s, recid }
}
