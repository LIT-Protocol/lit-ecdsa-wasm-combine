extern crate wasm_bindgen;
extern crate web_sys;
extern crate console_error_panic_hook;

use k256::AffinePoint;
use k256::PublicKey;
use k256::ecdsa::VerifyingKey;
use k256::elliptic_curve::generic_array::GenericArray;
use num_traits::Num;
use rand::AsByteSliceMut;
use wasm_bindgen::prelude::*;
use std::ops::BitAnd;
use std::ops::Shl;
use std::panic;
use num_bigint::BigUint as BigInt;

// pub mod lib_old;

pub const CURVE_ORDER: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
    0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b, 0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41,
];

 #[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

extern crate num_bigint;
extern crate num_integer;
extern crate num_traits;
extern crate rand;
extern crate k256;


use k256::Scalar as FE;
// use k256::AffinePoint as GE;
use k256::FieldBytes;
use num_integer::Integer;

#[derive(Clone, PartialEq, Debug,)]
struct Signature {
    pub r: FE,
    pub s: FE,
}

#[derive(Clone, PartialEq, Debug)]
pub struct SignatureRecid {
    pub r: FE,
    pub s: FE,
    pub recid: u8,
}

#[derive(Clone,Debug,Serialize,Deserialize)]
pub struct SignatureRecidHex {
    pub r: String,
    pub s: String,
    pub recid: u8,
}

//use web_sys::console;   // for logging to the JS console
fn test_bit(val: BigInt, _bit: usize) -> bool {
    let one = BigInt::from(1 as u16);
    let one_shl = &one.shl(_bit).clone();
    let one = BigInt::from(1 as u16);
    val.bitand(one_shl) == one
}
#[allow(non_snake_case)]
#[wasm_bindgen]
pub fn combine_signature(R_x: &str, R_y: &str, shares: &str) -> String {
    panic::set_hook(Box::new(console_error_panic_hook::hook));
    
    let shares_raw : Vec<String> = serde_json::from_str(&shares).unwrap();
    let mut shares: Vec<FE>  = Vec::new();

    for share in shares_raw {
        // let mut slice = hex::decode(&share).unwrap();
        // let slice = slice.as_byte_slice_mut();
        // let bytes = FieldBytes::from_mut_slice(slice);
        // shares.push( FE::from_bytes_reduced(bytes) );
        shares.push( hex_to_scalar( &share).unwrap());
    }

    let R_x = BigInt::from_str_radix(R_x,16).unwrap();
    println!("R_x: {}", R_x );
    let R_y = BigInt::from_str_radix(R_y, 16).unwrap();
    println!("R_y: {}", R_y );

    let sig = combine_signature_internal(        
        R_x,
        R_y,
        &shares,
    );
    
    let sigHex = SignatureRecidHex {
        r:  hex::encode( &sig.r.to_bytes() ),
        s: hex::encode( &sig.s.to_bytes() ),
        recid : sig.recid
    };

    serde_json::to_string(&sigHex).unwrap()
}

pub fn hex_to_scalar(hex_val: &str) -> Result<FE, ()> {

    let mut slice = hex::decode(hex_val).unwrap();
        let slice = slice.as_byte_slice_mut();
        let bytes = FieldBytes::from_mut_slice(slice);

        Ok( FE::from_bytes_reduced(bytes))
}

pub fn hex_to_pubkey(hex_val: &str) -> Result<PublicKey, ()> {
    let mut slice = hex::decode(hex_val).unwrap();
    let bytes = slice.as_byte_slice_mut();
    let pubkey =     PublicKey::from_sec1_bytes(bytes).expect("Error decoding pubkey from bytes");
    Ok(pubkey)
}

pub fn hex_to_verifying_key(hex_val: &str) -> Result<VerifyingKey, ()> {
    let mut slice = hex::decode(hex_val).unwrap();
    let bytes = slice.as_byte_slice_mut();
    let pubkey =     VerifyingKey::from_sec1_bytes(bytes).expect("Error decoding verifying key from bytes");
    Ok(pubkey)
}

// pub fn hex_to_digest_array(hex_val: &str) -> Result<bool, () >
// {
    
//     let mut slice = hex::decode(hex_val).unwrap();
//     let slice = slice.as_byte_slice_mut();


//     Ok(true)
// }

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
    
    let s_bn = BigInt::from_bytes_be(&s.to_bytes());

    let x_mode_floor_vec = local_x.mod_floor(&q).to_bytes_be();
    let x_mod_floor = x_mode_floor_vec.as_slice();
    let r: FE =  FE::from_bytes_reduced( FieldBytes::from_slice(x_mod_floor) );
   
    let _ry: BigInt = local_y.mod_floor(&q);
    
    // Calculate recovery id
    let is_ry_odd = test_bit(local_y, 0);
    
    let mut recid = if is_ry_odd { 1 } else { 0 };    
    
    let s_tag_bn = q - &s_bn;
    
    if s_bn > s_tag_bn {
        s = FE::from_bytes_reduced(FieldBytes::from_slice(&s_tag_bn.to_bytes_be()));
        recid ^= 1;
    }

    SignatureRecid { r, s, recid }
}



 #[cfg(test)]
 #[allow(non_snake_case)]
 mod tests {
    
    use crate::combine_signature;
    // use crate::hex_to_pubkey;
    use crate::hex_to_scalar;
    use crate::SignatureRecidHex;
    use crate::hex_to_verifying_key;
    use k256::ecdsa::Signature;
    // use k256::ecdsa::signature::DigestVerifier;
    use k256::ecdsa::signature::Verifier;
    
    // What are these tests?   
    // The data below is pulled from the console output generated when running tests in the LIT node code.  
    // The values have been valided inside thoses tests, but we could probably do a clearer test with actual primitives!
    #[test]
    fn simple_sign_test_10_of_10() {
    
        let R_x = "63a62e7c00f34a9de2fb55c99e672bb347b23b75991f4217dfbe31a09b627b22";

        let R_y = "1a87eb5a02a91ba8ae27ed404bae489de2616dab6f65894294e42a1022b0fdfe"; 

        let s_vec = "[\"4e52aeaed3e2e07977e2d0271b0ba4d8ecaa92aad7574496c5c51aa99a1fd1a1\" ,
            \"4f300a5d03a85c88bc7d85d5b29b3cd608c1fa1146c41d170f65e750f9ea0264\",
            \"95b1b520b25addae748e4f1cbf2c79afcef578da3285c8de71df35ba77d9930d\",
            \"c323d0f7f0626e62175539607a4205695dad2ce9362398390808a64acfc92c1f\",
            \"49263cfa45c1a1fd9e57e0e9a5afa7435c588e37a9c811809aa7feccf08a21a9\",
            \"ebd46fde3c122047f883efca7d5557e18b0f99543a8e4e1f88e69771b53a2648\",
            \"74e96f26cbc17cacee056abf4d822f76d8ad0829f6a230d8ddc239e4e1a1eef5\",
            \"87d1c86bdf1c82e6d887da3b10b26d51d33693ede49f4d0391d74a2266eb1e94\",
            \"aff1748ee300f71d07acd1a488a4af55ea6b5abcdd7e4b43dcd42536f3e3e7c9\",
            \"1b7b48af435ad3a8ee722795bc2aba16a7e92fe3a882e47664d1beb644b88de7\"]";

        let result = combine_signature(R_x, R_y,  s_vec);

        assert_eq!(
            result, "{\"r\":\"63a62e7c00f34a9de2fb55c99e672bb347b23b75991f4217dfbe31a09b627b22\",\"s\":\"0c851f3232a9ea4dec34129d32e199d75dbacfbda00d512e9b3afc8d0e74e7ea\",\"recid\":1}"
        
        );
    }


    #[test]
    fn simple_sign_test_2_of_3_with_pkp() {
    
        // let message = "Lit Protocol Rocks!"; //.to_string(); //.into_bytes();
        // let hex_pubkey = "045f6043924d928c544b0f4ace27913e9f9823fe6319c109b36acace12f5e338c3a0081aa220e23337aac219bbe84f278e428ee882e6661842f31e24ea46a34c02";
        // let digest = "4c69742050726f746f636f6c20526f636b7321";
        let R_x = "f485c4485a59a2c6854b9cd9b04d071f65e8fd009885834a1368670d79ec96c7";

        let R_y = "9e378f07d922a06a1c1ca1ef1e8458f27f5e9c004f78a51ccc86a46368259bb2"; 

        let s_vec = "[
            \"304b56d7e5fb1d8837f443089bf03fdae99501aa52c7e2973ac2687356ca176b\",
            \"fa31c7ca31101d16da36f61c40f04451da412cb16852461db6d5b409c7eac1a8\"
            ]";

        let result = combine_signature(R_x, R_y,  s_vec);

        assert_eq!(
            result, "{\"r\":\"f485c4485a59a2c6854b9cd9b04d071f65e8fd009885834a1368670d79ec96c7\",\"s\":\"2a7d1ea2170b3a9f122b3924dce0842e092751750bd1887931c5bdf04e7e97d2\",\"recid\":0}"
        );

        let _sig : SignatureRecidHex = serde_json::from_str(&result).expect("Error decoding r,s,recId to signature");

       // assert_eq!(verify_signature(msg, &sig.r, &sig.s, &hex_pubkey).unwrap(), true);


    }


    fn verify_signature(msg: &str, hex_r: &str, hex_s: &str, hex_pubkey: &str) -> Result<bool, ()> {
        
        let r = hex_to_scalar(hex_r).unwrap();
        let s = hex_to_scalar(hex_s).unwrap();

        let msg = msg.as_ref();

        let sig = Signature::from_scalars(r, s).unwrap();
        
        let verifying_key = hex_to_verifying_key(hex_pubkey).unwrap();
        

        let result = verifying_key.verify(msg, &sig);
        
        if result.is_err() {
            println!("{:?} \n {:?} \n {:?}", sig, verifying_key, &result.unwrap_err());
            
            return Ok(false);
        }
        

        Ok(true)
        

    }

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