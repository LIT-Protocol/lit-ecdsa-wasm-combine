extern crate console_error_panic_hook;
extern crate wasm_bindgen;
extern crate web_sys;

use elliptic_curve::sec1::ToEncodedPoint;
use js_sys::Array;
use k256::Secp256k1;
use std::panic;
use wasm_bindgen::prelude::*;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

extern crate k256;
extern crate num_bigint;
extern crate num_integer;
extern crate num_traits;
extern crate rand;

mod combiners;
mod errors;
mod models;

#[cfg(test)]
mod tests;

#[wasm_bindgen]
#[doc = "Entry point for recombining signatures."]
pub fn combine_signature(in_shares: Array, key_type: u8) -> String {
    panic::set_hook(Box::new(console_error_panic_hook::hook));

    let mut shares = Vec::new();
    for i in 0..in_shares.length() {
        shares.push(in_shares.get(i).as_string().unwrap());
    }

    let sig_hex = match key_type {
        // 2 => combiners::k256_zg::combine_signature(R_x, R_y, shares),
        2 => combiners::k256_cait_sith::combine_signature(shares),
        3 => combiners::p256_cait_sith::combine_signature(shares),
        _ => panic!("Invalid key type"),
    };

    sig_hex
}

#[wasm_bindgen]
#[doc = "Entry point for compute hd derived public keys"]
pub fn compute_public_key(id: String, public_keys: Array, key_type: u8) -> String {
    panic::set_hook(Box::new(console_error_panic_hook::hook));
    /*
        compressed -> 33
        uncompressed -> 65
    */
    let mut hd_pub_keys = Vec::with_capacity(public_keys.length() as usize);
    for pubkey in public_keys.iter() {
        let pubkey = pubkey.as_string();
        if pubkey.is_none() {
            panic!("Could not covnert pubkey to string, aborting");
        }
        let pubkey = pubkey.unwrap();
        let hex_pub_key = hex::decode(pubkey);
        if hex_pub_key.is_err() {
            panic!(
                "Error while converting pubkey to hex encoding {}",
                hex_pub_key.err().unwrap()
            );
        }
        let hex_pub_key = hex_pub_key.unwrap();
        let point = convert_to_point(hex_pub_key.as_slice());
        hd_pub_keys.push(point);
    }

    let id = id.as_bytes();
    let deriver = match key_type {
        2 => combiners::hd_ecdsa::HdKeyDeriver::<Secp256k1>::new(id, combiners::hd_ecdsa::CXT),
        _ => panic!("Invalid key type")
    };
    
    if deriver.is_err() {
        panic!("Could not derive publick key {}", deriver.err().unwrap())
    }

    let deriver = deriver.unwrap();
    let pubkey = deriver.compute_public_key(&hd_pub_keys.as_slice());
    let pubkey = hex::encode(pubkey.to_encoded_point(true).as_bytes());

    pubkey
}

fn convert_to_point(input: &[u8]) -> k256::ProjectivePoint {
    use k256::elliptic_curve::sec1::FromEncodedPoint;

    k256::ProjectivePoint::from_encoded_point(&k256::EncodedPoint::from_bytes(input).unwrap())
        .unwrap()
}

// // This is a representation of the GG20 version of recombination.

// fn output_signature(ls: &LocalSignature, s_vec: &Vec<FE>) -> Result<SignatureRecid, Error> {
//     let mut s = s_vec.iter().fold(ls.s_i.clone(), |acc, x| acc + x);

//     let s_bn = s.to_big_int();

//     let r: FE = ECScalar::from(&ls.R.x_coor().unwrap().mod_floor(&FE::q())); // q is the group order for the Secp256k1 curve.

//     let ry: BigInt = ls.R.y_coor().unwrap().mod_floor(&FE::q());

//     /*
//      Calculate recovery id - it is not possible to compute the public key out of the signature
//      itself. Recovery id is used to enable extracting the public key uniquely.
//      1. id = R.y & 1
//      2. if (s > curve.q / 2) id = id ^ 1
//     */
//     let is_ry_odd = ry.test_bit(0);
//     let mut recid = if is_ry_odd { 1 } else { 0 };
//     let s_tag_bn = FE::q() - &s_bn;
//     if s_bn > s_tag_bn {
//         s = ECScalar::from(&s_tag_bn);
//         recid ^= 1;
//     }

//     let sig = SignatureRecid { r, s, recid };

//     let ver = verify(&sig, &ls.y, &ls.m).is_ok();
//     match ver {
//         true => Ok(sig),
//         false => Err(Error::InvalidSig),
//     }
// }

// // verify's the signature - this function brings a lot of additional library overhead into scope
// // and with the inclusion of web3/ethers in the JS side of the SDK, we aren't providing the users with any
// // additional information.

// fn verify(sig: &SignatureRecid, y: &GE, message: &BigInt) -> Result<(), Error> {
//     let b = sig.s.invert();
//     let a: FE = ECScalar::from(message);
//     let u1 = a * &b;
//     let u2 = sig.r.clone() * &b;

//     let g: GE = ECPoint::generator();
//     let gu1 = &g * &u1;
//     let yu2 = y * &u2;
//     // can be faster using shamir trick
//     if sig.r.clone() == ECScalar::from(&(gu1 + yu2).x_coor().unwrap().mod_floor(&FE::q())) {
//         Ok(())
//     } else {
//         Err(Error::InvalidSig)
//     }
// }
