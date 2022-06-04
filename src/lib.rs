extern crate wasm_bindgen;
extern crate web_sys;
extern crate console_error_panic_hook;

use curv::arithmetic::traits::BitManipulation;
//use num_bigint::BigInt;
use num_traits::Num;
use wasm_bindgen::prelude::*;
use std::panic;



#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

extern crate num_bigint;
extern crate num_integer;
extern crate num_traits;
//extern crate rand;
extern crate rand;
// extern crate cryptoxide;

pub mod curv;

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
enum Error {
    InvalidKey,
    InvalidSS,
    InvalidCom,
    InvalidSig,
}
#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum ErrorKey {
    InvalidPublicKey,
}

use curv::arithmetic::num_bigint::BigInt;
use curv::elliptic::curves::secp256_k1::{  FE, GE, SK}; //, Secp256k1Scalar};
use curv::elliptic::curves::traits::*;
use num_integer::Integer;

#[derive(Clone, Serialize, Deserialize)]
struct LocalSignature {
    pub r: FE,
    pub R: GE,
    pub s_i: FE,
    pub m: BigInt,
    pub y: GE,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
struct Signature {
    pub r: FE,
    pub s: FE,
}

#[derive(Clone, PartialEq, Debug, Serialize, Deserialize)]
pub struct SignatureRecid {
    pub r: FE,
    pub s: FE,
    pub recid: u8,
}

//use web_sys::console;   // for logging to the JS console

#[wasm_bindgen]
pub fn combine_signature(R_x: &str, R_y: &str, shares: &str) -> String {
    panic::set_hook(Box::new(console_error_panic_hook::hook));
    
    let shares: Vec<FE> = serde_json::from_str(&shares).unwrap();
    let R_x = BigInt::from_str_radix(R_x,16).unwrap();
    println!("R_x: {}", R_x );
    let R_y = BigInt::from_str_radix(R_y, 16).unwrap();
    println!("R_y: {}", R_y );

    let sig = combine_signature_internal(        
        R_x,
        R_y,
        &shares,
    );
    serde_json::to_string(&sig).unwrap()
}


pub fn combine_signature_internal(
    local_x: BigInt,
    local_y: BigInt,
    s_vec: &Vec<FE>,
) -> SignatureRecid {
    // to print the shares for debugging
    // console::log_1(&"combine_signature_internal".into());
    // for (idx, s) in s_vec.iter().enumerate() {
    //     console::log_2(&idx.into(), &s.to_big_int().to_str_radix(16).into());
    // }

    println!("local_x : {}", local_x);
    println!("local_y : {}", local_y);


    // reduce -> but what about reference?
    let init = s_vec[0].clone();  
    // console::log_2(&"init:".into(), &init.to_big_int().to_str_radix(16).into() );
    let mut s = s_vec.iter().skip(1).fold(init, |acc, x| acc + x);
    
    let s_bn = s.to_big_int();

    let r: FE = ECScalar::from(&local_x.mod_floor(&FE::q())); // q is the group order for the Secp256k1 curve.
   
    let ry: BigInt = local_y.mod_floor(&FE::q());
    
    // Calculate recovery id
    let is_ry_odd = local_y.test_bit(0);
    
    let mut recid = if is_ry_odd { 1 } else { 0 };    
    
    let s_tag_bn = FE::q() - &s_bn;
    
    if s_bn > s_tag_bn {
        s = ECScalar::from(&s_tag_bn);
        recid ^= 1;
    }


    SignatureRecid { r, s, recid }

}


// This is a representation of the GG20 version of recombination.

fn output_signature(ls: &LocalSignature, s_vec: &Vec<FE>) -> Result<SignatureRecid, Error> {
    let mut s = s_vec.iter().fold(ls.s_i.clone(), |acc, x| acc + x);

    let s_bn = s.to_big_int();

    let r: FE = ECScalar::from(&ls.R.x_coor().unwrap().mod_floor(&FE::q())); // q is the group order for the Secp256k1 curve.

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

// verify's the signature - this function brings a lot of additional library overhead into scope
// and with the inclusion of web3/ethers in the JS side of the SDK, we aren't providing the users with any
// additional information.

fn verify(sig: &SignatureRecid, y: &GE, message: &BigInt) -> Result<(), Error> {
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
    use std::str::FromStr;

    use num_bigint::BigUint;
    use num_traits::Num;

    use crate::{
        combine_signature,
        curv::elliptic::curves::{
            secp256_k1::{Secp256k1Point, Secp256k1Scalar, FE},
            traits::{ECPoint, ECScalar},
        },
        output_signature, LocalSignature,
    };

    #[test]
    fn simple_sign_test() {
        //let ls = "{\"r\":\"63a62e7c00f34a9de2fb55c99e672bb347b23b75991f4217dfbe31a09b627b22\",\"R\":{\"x\":\"63a62e7c00f34a9de2fb55c99e672bb347b23b75991f4217dfbe31a09b627b22\",\"y\":\"816b4d34f48365ae5df7e965d9c0292531893aa40493bc5c327e6ee39512ef31\"},\"s_i\":\"4e52aeaed3e2e07977e2d0271b0ba4d8ecaa92aad7574496c5c51aa99a1fd1a1\",\"m\":[2825099285,210371760],\"y\":{\"x\":\"bfc168dfb3e09b2899c6829bae5c99025a5d4bab2cb5b2a2b7be176379ad3a2d\",\"y\":\"18e7e02fbac1a28c0057ebb707ccb00b729cd37c0aadd42c883a6ba26581e221\"}}";

        let R_x = "d51e14e03d860718edccbbbca063c1e9b70379840cc40e59bd1bcdad095e460d";

        let R_y = "1a87eb5a02a91ba8ae27ed404bae489de2616dab6f65894294e42a1022b0fdfe"; 

        let s_vec = "[
            \"fe0bd6b5e65518fe6f05affe71c6c39bdffaa34be943e08b9172ccee8453e45f\", 
            \"fc6ea88a46c187c002ec47e8abfb580557ade42a14684950acedbb4ab9bbb8af\",
            \"ee144d6f11fd94b20f4bb51468eaf341b1072a481d5944a6a4e990076a1820dc\",
            \"65fe6687f6eefc8579f4738bd7b608ac1fa7a7068cde028f54e77d8c67030e27\",
            \"4e0e1b7531bd76c4ae9feb99bad1c3a2dab93cecb37bb970ba97a4bdcc75d161\",
            \"52b16941e6e6478a8bda762400d0a5d382983282f94a8e1bc301edd62050798c\",
            \"9f88a9a696e397172ab5faa20f869d37128854eb237d47d612b877441ac232ee\",
            \"6e7a21bc5ea6064268ecf258cb1ecc500763d8a4f73004fc6c9c0c228e114ef\",
            \"c4db7ae435602caeedc2e39b43cc53dc5ae2162fd5cf8d71ad30b6c46a9d1731\",
            \"2a6491aac89f4e51cd423f475ae8ff62118cfbaf0d10b131572309f9e367874d\"]";

        let result = combine_signature(R_x, R_y,  s_vec);

        println!("Result: {}", result);

        // assert_eq!(
        //     result, "{\"r\":\"d51e14e03d860718edccbbbca063c1e9b70379840cc40e59bd1bcdad095e460d\",\"s\":\"c851f3232a9ea4dec34129d32e199d75dbacfbda00d512e9b3afc8d0e74e7ea\",\"recid\":0}"
        // );
    }

    #[test]
    fn simple_sign_test2() {
    
        let R_x = "d51e14e03d860718edccbbbca063c1e9b70379840cc40e59bd1bcdad095e460d";

        let R_y = "1a87eb5a02a91ba8ae27ed404bae489de2616dab6f65894294e42a1022b0fdfe"; 

        let s_vec = "[\"4e52aeaed3e2e07977e2d0271b0ba4d8ecaa92aad7574496c5c51aa99a1fd1a1\" ,\"4f300a5d03a85c88bc7d85d5b29b3cd608c1fa1146c41d170f65e750f9ea0264\",\"95b1b520b25addae748e4f1cbf2c79afcef578da3285c8de71df35ba77d9930d\",\"c323d0f7f0626e62175539607a4205695dad2ce9362398390808a64acfc92c1f\",\"49263cfa45c1a1fd9e57e0e9a5afa7435c588e37a9c811809aa7feccf08a21a9\",\"ebd46fde3c122047f883efca7d5557e18b0f99543a8e4e1f88e69771b53a2648\",\"74e96f26cbc17cacee056abf4d822f76d8ad0829f6a230d8ddc239e4e1a1eef5\",\"87d1c86bdf1c82e6d887da3b10b26d51d33693ede49f4d0391d74a2266eb1e94\",\"aff1748ee300f71d07acd1a488a4af55ea6b5abcdd7e4b43dcd42536f3e3e7c9\",\"1b7b48af435ad3a8ee722795bc2aba16a7e92fe3a882e47664d1beb644b88de7\"]";

        let result = combine_signature(R_x, R_y,  s_vec);

        assert_eq!(
            result, "{\"r\":\"63a62e7c00f34a9de2fb55c99e672bb347b23b75991f4217dfbe31a09b627b22\",\"s\":\"c851f3232a9ea4dec34129d32e199d75dbacfbda00d512e9b3afc8d0e74e7ea\",\"recid\":0}"
        
        );
    }


    #[test]
    // Very basic test here, TODO: suggest better testing
    fn simple_sign_test_from_objects() {
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

        // let ysr = y.bytes_compressed_to_big_int().to_str_radix(16);
        // let ysr_x = y.x_coor().unwrap().to_bigint().unwrap().to_str_radix(16);
        // let ysr_y = y.y_coor().unwrap().to_bigint().unwrap().to_str_radix(16);

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

        // let Rsr = R.bytes_compressed_to_big_int().to_str_radix(16);
        // let Rsr_x = R.x_coor().unwrap().to_bigint().unwrap().to_str_radix(16);
        // let Rsr_y = R.y_coor().unwrap().to_bigint().unwrap().to_str_radix(16);

        // let msr = m.to_string();

        let ls = LocalSignature { r, R, s_i, m, y };

        let ls_l = serde_json::to_string(&ls).unwrap();
        let ls_v = serde_json::to_string(&s_vec).unwrap();

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
