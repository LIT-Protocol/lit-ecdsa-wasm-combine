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
        3 => combiners::k256_cait_sith::combine_signature(shares),
        4 => combiners::p256_cait_sith::combine_signature(shares),
        _ => panic!("Invalid key type"),
    };

    sig_hex
}

#[wasm_bindgen]
#[doc = "Entry point for compute hd derived public keys"]
pub fn compute_public_key(id: String, public_keys: Array) -> String {
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
        let a_p = convert_to_point(hex_pub_key.as_slice());
        hd_pub_keys.push(a_p);
    }

    let id = id.as_bytes();

    let deriver = combiners::hd_ecdsa::HdKeyDeriver::<Secp256k1>::new(id, combiners::hd_ecdsa::CXT);

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
