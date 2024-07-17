use crate::models::SignatureRecidHex;
use k256::elliptic_curve::scalar::ScalarPrimitive;
use k256::ecdsa::VerifyingKey;
use num_bigint::BigUint as BigInt;
use num_traits::Num;
use std::ops::BitAnd;
use std::ops::Shl;

pub const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

use k256::Scalar as FE; // Field Element
use num_integer::Integer;

// #[derive(Clone, PartialEq, Debug)]
// struct Signature {
//     pub r: FE,
//     pub s: FE,
// }

#[derive(Clone, PartialEq, Debug)]
pub struct SignatureRecid {
    pub r: FE,
    pub s: FE,
    pub recid: u8,
}

//use web_sys::console;   // for logging to the JS console
#[doc = "Tests a bit of a bigint."]
fn test_bit(val: BigInt, _bit: usize) -> bool {
    let one = BigInt::from(1 as u16);
    let one_shl = &one.shl(_bit).clone();
    let one = BigInt::from(1 as u16);
    val.bitand(one_shl) == one
}

pub fn combine_signature(shares: Vec<&str>) -> String {
    let mut shares_parts: Vec<Vec<FE>> = Vec::new();
    let result = "".to_string();
    //combine_signature_old(&R_x, &R_y, &shares_parts);
    result
}
#[doc = "Entry point for recombining signatures."]
pub fn combine_signature_old(big_r_x: &str, big_r_y: &str, shares: &str) -> String {
    let shares_raw: Vec<String> = serde_json::from_str(&shares).unwrap();
    let mut shares: Vec<FE> = Vec::new();

    for share in shares_raw {
        if share.len() > 1 {
            shares.push(hex_to_scalar(&share).unwrap());
        }
    }

    let big_r_x = BigInt::from_str_radix(big_r_x, 16).unwrap();
    println!("R_x: {}", big_r_x);
    let big_r_y = BigInt::from_str_radix(big_r_y, 16).unwrap();
    println!("R_y: {}", big_r_y);

    let sig = combine_signature_internal(big_r_x, big_r_y, &shares);

    let sig_hex = SignatureRecidHex {
        r: hex::encode(&sig.r.to_bytes()),
        s: hex::encode(&sig.s.to_bytes()),
        recid: sig.recid,
    };

    serde_json::to_string(&sig_hex).unwrap()
}

#[doc = "Converts hex strings to Scalers as defined in RustCrypto's K256 crate."]
pub fn hex_to_scalar(hex_val: &str) -> Result<FE, ()> {
    let mut hex_val = hex_val.to_string();
    if hex_val.len() % 2 == 1 {
        // if length is odd, add a zero at the front
        hex_val.insert(0, '0');
    }

    let slice = hex::decode(hex_val).unwrap();
    let slice = slice.as_slice();

    let sp = ScalarPrimitive::from_slice(slice).expect("Error decoding scalar from bytes");
    Ok(FE::from(sp))
}

// #[doc = "Converts hex strings to Public Keys as defined in RustCrypto's K256 crate."]
// pub fn hex_to_pubkey(hex_val: &str) -> Result<PublicKey, ()> {

//      let mut hex_val = hex_val.to_string();
//     if hex_val.len() % 2 == 1 {
//         // if length is odd, add a zero at the front
//         hex_val.insert(0, '0');
//     }
//     let mut slice = hex::decode(hex_val).unwrap();
//     let bytes = slice.as_byte_slice_mut();
//     let pubkey = PublicKey::from_sec1_bytes(bytes).expect("Error decoding pubkey from bytes");
//     Ok(pubkey)
// }

#[doc = "Converts hex strings to Verifiying Keys as defined in RustCrypto's K256 crate."]
pub fn hex_to_verifying_key(hex_val: &str) -> Result<VerifyingKey, ()> {
    let mut hex_val = hex_val.to_string();
    if hex_val.len() % 2 == 1 {
        // if length is odd, add a zero at the front
        hex_val.insert(0, '0');
    }
    let slice = hex::decode(hex_val).unwrap();
    let bytes = slice.as_slice();
    let pubkey =
        VerifyingKey::from_sec1_bytes(bytes).expect("Error decoding verifying key from bytes");
    Ok(pubkey)
}

#[doc = "Basic math required to agregate signature shares and generate the final sig."]
pub fn combine_signature_internal(
    local_x: BigInt,
    local_y: BigInt,
    s_vec: &Vec<FE>,
) -> SignatureRecid {
    // println!("local_x : {}", local_x);
    // println!("local_y : {}", local_y);

    let q = BigInt::from_bytes_be(CURVE_ORDER.as_ref());
    // reduce -> but what about reference?
    let init = s_vec[0].clone();
    let mut s = s_vec.iter().skip(1).fold(init, |acc, x| acc + x);

    let g_a = s.to_bytes();
    let g_a = g_a.as_slice();
    let s_bn = BigInt::from_bytes_be(&g_a);

    let mut x_mode_floor_vec = local_x.mod_floor(&q).to_bytes_be();
    // if x_mode_floor_vec.len()  is odd prepend a zero
    if x_mode_floor_vec.len() % 2 == 1 {
        let mut x_mod_floor = vec![0];
        x_mod_floor.extend_from_slice(&x_mode_floor_vec);
        x_mode_floor_vec = x_mod_floor;
    }

    let x_mod_floor = x_mode_floor_vec.as_slice();

    let x_sp = ScalarPrimitive::from_slice(x_mod_floor).expect("Error decoding scalar from bytes");
    let r: FE = FE::from(x_sp);
    //let r: FE = FE::from_bytes_reduced(FieldBytes::from_slice(x_mod_floor));

    let _ry: BigInt = local_y.mod_floor(&q);

    // Calculate recovery id
    let is_ry_odd = test_bit(local_y, 0);

    let mut recid = if is_ry_odd { 1 } else { 0 };

    let s_tag_bn = q - &s_bn;

    if s_bn > s_tag_bn {
        let s_sp = ScalarPrimitive::from_slice(&s_tag_bn.to_bytes_be())
            .expect("Error decoding scalar from bytes");
        s = FE::from(s_sp);
        // s = FE::from_bytes_reduced(FieldBytes::from_slice(&s_tag_bn.to_bytes_be()));
        recid ^= 1;
    }

    SignatureRecid { r, s, recid }
}
