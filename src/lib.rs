extern crate wasm_bindgen;
use curv::arithmetic::traits::BitManipulation;
use wasm_bindgen::prelude::*;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

extern crate num_bigint;
extern crate num_integer;
extern crate num_traits;
extern crate rand;
extern crate zeroize;

extern crate cryptoxide;

pub mod curv;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Error {
    InvalidKey,
    InvalidSS,
    InvalidCom,
    InvalidSig,
}
#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum ErrorKey {
    InvalidPublicKey,
}

pub enum ErrorSS {
    VerifyShareError,
}

use curv::arithmetic::num_bigint::BigInt;
use curv::elliptic::curves::secp256_k1::{Secp256k1Scalar, FE, GE, PK};
use curv::elliptic::curves::traits::*;
use num_integer::Integer;

// #[derive(Clone, Serialize, Deserialize)]
// pub struct LocalSignature {
//     pub l_i: FE,
//     pub rho_i: FE,
//     pub R: GE,
//     pub s_i: FE,
//     pub m: BigInt,
//     pub y: GE,
// }

#[derive(Clone, Serialize, Deserialize)]
pub struct LocalSignature {
    pub r: FE,
    pub R: GE,
    pub s_i: FE,
    pub m: BigInt,
    pub y: GE,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct Signature {
    pub r: FE,
    pub s: FE,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SignatureRecid {
    pub r: FE,
    pub s: FE,
    pub recid: u8,
}

#[wasm_bindgen]
pub fn combine_signature(ls: String, s_vec: String) -> String {
    let ls: LocalSignature = serde_json::from_str(&ls).unwrap();
    let s_vec: Vec<FE> = serde_json::from_str(&s_vec).unwrap();

    let sig = output_signature(&ls, &s_vec);

    if sig.is_ok() {
        let sig = sig.unwrap();
        return serde_json::to_string(&sig).unwrap();
    }

    String::from("Failed")
}

pub fn output_signature(ls: &LocalSignature, s_vec: &Vec<FE>) -> Result<SignatureRecid, Error> {
    let mut s = s_vec.iter().fold(ls.s_i.clone(), |acc, x| acc + x);

    let s_bn = s.to_big_int();

    let r: FE = ECScalar::from(&ls.R.x_coor().unwrap().mod_floor(&FE::q())); // q is the group order for the Secp256k1 curve.

    let qsv = FE::q().to_str_radix(16);
    let rsv = r.to_big_int().to_str_radix(16);

    let ry: BigInt = ls.R.y_coor().unwrap().mod_floor(&FE::q());

    /*
     Calculate recovery id - it is not possible to compute the public key out of the signature
     itself. Recovery id is used to enable extracting the public key uniquely.
     1. id = R.y & 1
     2. if (s > curve.q / 2) id = id ^ 1
    */

    let is_ry_odd = ry.test_bit(0);
    let mut recid = if is_ry_odd { 1 } else { 0 };
    let s_tag_bn = FE::q() - &s_bn;
    if s_bn > s_tag_bn {
        s = ECScalar::from(&s_tag_bn);
        recid ^= 1;
    }

    let sig = SignatureRecid { r, s, recid };

    let ver = verify(&sig, &ls.y, &ls.m).is_ok();
    match ver {
        true => Ok(sig),
        false => Err(Error::InvalidSig),
    }
}

pub fn verify(sig: &SignatureRecid, y: &GE, message: &BigInt) -> Result<(), Error> {
    let b = sig.s.invert();
    let a: FE = ECScalar::from(message);
    let u1 = a * &b;
    let u2 = sig.r.clone() * &b;

    let g: GE = ECPoint::generator();
    let gu1 = &g * &u1;
    let yu2 = y * &u2;
    // can be faster using shamir trick
    if sig.r.clone() == ECScalar::from(&(gu1 + yu2).x_coor().unwrap().mod_floor(&FE::q())) {
        Ok(())
    } else {
        Err(Error::InvalidSig)
    }
}

#[cfg(test)]
mod tests {
    use std::{convert::TryInto, str::FromStr};

    use num_bigint::{BigUint, ToBigInt, ToBigUint};
    use num_traits::Num;

    use crate::{
        curv::elliptic::curves::{
            secp256_k1::{Secp256k1Point, Secp256k1Scalar, FE, GE, PK, SK},
            traits::{ECPoint, ECScalar},
        },
        output_signature, LocalSignature,
    };

    #[test]
    // Very basic test here, TODO: suggest better testing
    fn simple_sign_test() {
        let mut s_vec: Vec<FE> = Vec::new();
        s_vec.push(h2s(
            "4f300a5d03a85c88bc7d85d5b29b3cd608c1fa1146c41d170f65e750f9ea0264",
        ));
        s_vec.push(h2s(
            "95b1b520b25addae748e4f1cbf2c79afcef578da3285c8de71df35ba77d9930d",
        ));
        s_vec.push(h2s(
            "c323d0f7f0626e62175539607a4205695dad2ce9362398390808a64acfc92c1f",
        ));
        s_vec.push(h2s(
            "49263cfa45c1a1fd9e57e0e9a5afa7435c588e37a9c811809aa7feccf08a21a9",
        ));
        s_vec.push(h2s(
            "ebd46fde3c122047f883efca7d5557e18b0f99543a8e4e1f88e69771b53a2648",
        ));
        s_vec.push(h2s(
            "74e96f26cbc17cacee056abf4d822f76d8ad0829f6a230d8ddc239e4e1a1eef5",
        ));
        s_vec.push(h2s(
            "87d1c86bdf1c82e6d887da3b10b26d51d33693ede49f4d0391d74a2266eb1e94",
        ));
        s_vec.push(h2s(
            "aff1748ee300f71d07acd1a488a4af55ea6b5abcdd7e4b43dcd42536f3e3e7c9",
        ));
        s_vec.push(h2s(
            "1b7b48af435ad3a8ee722795bc2aba16a7e92fe3a882e47664d1beb644b88de7",
        ));

        let r: Secp256k1Scalar =
            h2s("63a62e7c00f34a9de2fb55c99e672bb347b23b75991f4217dfbe31a09b627b22");
        let s_i: Secp256k1Scalar =
            h2s("4e52aeaed3e2e07977e2d0271b0ba4d8ecaa92aad7574496c5c51aa99a1fd1a1");
        let m = BigUint::from_str("903539832027060245").unwrap();

        //  "3bfc168dfb3e09b2899c6829bae5c99025a5d4bab2cb5b2a2b7be176379ad3a2d",

        let yx = BigUint::from_str_radix(
            "bfc168dfb3e09b2899c6829bae5c99025a5d4bab2cb5b2a2b7be176379ad3a2d",
            16,
        )
        .unwrap();
        let yy = BigUint::from_str_radix(
            "18e7e02fbac1a28c0057ebb707ccb00b729cd37c0aadd42c883a6ba26581e221",
            16,
        )
        .unwrap();

        let y: Secp256k1Point = Secp256k1Point::from_coor(&yx, &yy);

        let ysr = y.bytes_compressed_to_big_int().to_str_radix(16);
        let ysr_x = y.x_coor().unwrap().to_bigint().unwrap().to_str_radix(16);
        let ysr_y = y.y_coor().unwrap().to_bigint().unwrap().to_str_radix(16);

        let rx = BigUint::from_str_radix(
            "63a62e7c00f34a9de2fb55c99e672bb347b23b75991f4217dfbe31a09b627b22",
            16,
        )
        .unwrap();
        let ry = BigUint::from_str_radix(
            "816b4d34f48365ae5df7e965d9c0292531893aa40493bc5c327e6ee39512ef31",
            16,
        )
        .unwrap();

        let R: Secp256k1Point = Secp256k1Point::from_coor(&rx, &ry);

        let Rsr = R.bytes_compressed_to_big_int().to_str_radix(16);
        let Rsr_x = R.x_coor().unwrap().to_bigint().unwrap().to_str_radix(16);
        let Rsr_y = R.y_coor().unwrap().to_bigint().unwrap().to_str_radix(16);

        let msr = m.to_string();
        // let r_bytes: &[u8; 33] = &r_bytes.try_into().unwrap();

        // let R = Secp256k1Point {
        //     purpose: "point",
        //     ge: PK::parse_compressed(r_bytes).unwrap(),
        // };

        let ls = LocalSignature { r, R, s_i, m, y };
        let result = output_signature(&ls, &s_vec).unwrap();
        let r = result.r.to_big_int().to_str_radix(16);
        let s = result.s.to_big_int().to_str_radix(16);

        assert_eq!(
            r,
            "63a62e7c00f34a9de2fb55c99e672bb347b23b75991f4217dfbe31a09b627b22"
        );
        assert_eq!(
            s,
            "c851f3232a9ea4dec34129d32e199d75dbacfbda00d512e9b3afc8d0e74e7ea"
        );
    }

    pub fn h2s(hex: &str) -> Secp256k1Scalar {
        ECScalar::from(&BigUint::from_str_radix(hex, 16).unwrap())
    }
}

// let r = ECScalar::from(&BigUint::from_bytes_be(&[
//     99, 166, 46, 124, 0, 243, 74, 157, 226, 251, 85, 201, 158, 103, 43, 179, 71, 178, 59,
//     117, 153, 31, 66, 23, 223, 190, 49, 160, 155, 98, 123, 34,
// ]));

// let s_i = ECScalar::from(
//     &BigUint::from_str_radix(
//         "4f300a5d03a85c88bc7d85d5b29b3cd608c1fa1146c41d170f65e750f9ea0264",
//         16,
//     )
//     .unwrap(),
// );

// let m = BigUint::from_bytes_be(&[12, 138, 4, 176, 168, 99, 152, 21]);

// // let y = ECPoint::from_bytes(&[
// //     3, 191, 193, 104, 223, 179, 224, 155, 40, 153, 198, 130, 155, 174, 92, 153, 2, 90, 93,
// //     75, 171, 44, 181, 178, 162, 183, 190, 23, 99, 121, 173, 58, 45,
// // ])
// // .unwrap();

// // let R = ECPoint::from_bytes(&[
// //     3, 99, 166, 46, 124, 0, 243, 74, 157, 226, 251, 85, 201, 158, 103, 43, 179, 71, 178,
// //     59, 117, 153, 31, 66, 23, 223, 190, 49, 160, 155, 98, 123, 34,
// // ])
// // .unwrap();

// let  p =    BigUint::from_str_radix("4bfc168dfb3e09b2899c6829bae5c99025a5d4bab2cb5b2a2b7be176379ad3a2d18e7e02fbac1a28c0057ebb707ccb00b729cd37c0aadd42c883a6ba26581e221", 16).unwrap().to_bytes_be();

// let y = ECPoint::from_bytes(&p).unwrap();
// let R = ECPoint::from_bytes(&p).unwrap();
