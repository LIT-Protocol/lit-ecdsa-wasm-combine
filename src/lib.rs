extern crate console_error_panic_hook;
extern crate wasm_bindgen;
extern crate web_sys;
use js_sys::Array;
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
mod models;
mod errors;
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
