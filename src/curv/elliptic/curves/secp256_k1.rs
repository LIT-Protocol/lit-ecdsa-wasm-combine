#![allow(non_snake_case)]
/*
    This file is part of Curv library
    Copyright 2018 by Kzen Networks
    (https://github.com/KZen-networks/curv)
    License MIT: <https://github.com/KZen-networks/curv/blob/master/LICENSE>
*/

// Secp256k1 elliptic curve utility functions (se: https://en.bitcoin.it/wiki/Secp256k1).
//
// In Cryptography utilities, we need to manipulate low level elliptic curve members as Point
// in order to perform operation on them. As the library secp256k1 expose only SecretKey and
// PublicKey, we extend those with simple codecs.
//
// The Secret Key codec: BigInt <> SecretKey
// The Public Key codec: Point <> SecretKey
//
extern crate getrandom;

use super::rand::{thread_rng, Rng};
// use super::secp256k1::util::{
//     // CURVE_ORDER,
//     // GENERATOR_X,
//     // GENERATOR_Y,
//     SECRET_KEY_SIZE,
//     RAW_PUBLIC_KEY_SIZE,
// };
use super::secp256k1::{PublicKey, SecretKey};
use super::traits::{ECPoint, ECScalar};
use curv::arithmetic::num_bigint::from;
use curv::arithmetic::num_bigint::BigInt;
use curv::arithmetic::traits::{Converter, Modulo};
use curv::cryptographic_primitives::hashing::constants::{
    CURVE_ORDER, GENERATOR_X, GENERATOR_Y, SECRET_KEY_SIZE, UNCOMPRESSED_PUBLIC_KEY_SIZE,
};
// use curv::cryptographic_primitives::hashing::hash_sha256::HSha256;
// use curv::cryptographic_primitives::hashing::traits::Hash;
use num_traits::Num;
use serde::de;
use serde::de::{MapAccess, Visitor};
use serde::ser::SerializeStruct;
use serde::ser::{Serialize, Serializer};
use serde::{Deserialize, Deserializer};
use std::fmt;
use std::ops::{Add, Mul};
use std::ptr;
use std::sync::atomic;

// extern crate zeroize;

use super::zeroize::Zeroize;

use super::secp256k1::curve::Scalar;

use ErrorKey;
pub type SK = SecretKey;
pub type PK = PublicKey;

#[derive(Clone, Debug)]
pub struct Secp256k1Scalar {
    purpose: &'static str,
    fe: SK,
}
#[derive(Clone, Debug)]
pub struct Secp256k1Point {
    pub purpose: &'static str,
    pub ge: PK,
}

pub type GE = Secp256k1Point;
pub type FE = Secp256k1Scalar;

impl Secp256k1Scalar {
    pub fn copy(&self) -> Secp256k1Scalar {
        Secp256k1Scalar {
            purpose: self.purpose,
            fe: self.fe.clone(),
        }
    }
}

impl Secp256k1Point {
    pub fn random_point() -> Secp256k1Point {
        let random_scalar: Secp256k1Scalar = Secp256k1Scalar::new_random();
        let base_point = Secp256k1Point::generator();
        let pk = base_point.scalar_mul(&random_scalar.get_element());
        Secp256k1Point {
            purpose: "random_point",
            ge: pk.get_element(),
        }
    }
    // To generate a random base point we take the hash of the curve generator.
    // This hash creates a random string which do not encode a valid (x,y) curve point.
    // Therefore we continue to hash the result until the first valid point comes out.
    // This function is a result of a manual testing to find
    // this minimal number of hashes and therefore it is written like this.
    // the prefix "2" is to complete for the right parity of the point
    // pub fn base_point2() -> Secp256k1Point {
    //     let g: Secp256k1Point = ECPoint::generator();
    //     let hash = HSha256::create_hash(&[&g.bytes_compressed_to_big_int()]);

    //     let hash = HSha256::create_hash(&[&hash]);

    //     let hash = HSha256::create_hash(&[&hash]);
    //     let mut hash_vec = BigInt::to_vec(&hash);
    //     let mut template: Vec<u8> = vec![2];
    //     template.append(&mut hash_vec);

    //     Secp256k1Point {
    //         purpose: "random",
    //         ge: PK::parse_slice(&template, None).unwrap(),
    //     }
    // }

    pub fn copy(&self) -> Secp256k1Point {
        Secp256k1Point {
            purpose: self.purpose,
            ge: self.ge.clone(),
        }
    }
}

impl Zeroize for FE {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(self, FE::zero()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl ECScalar<SK> for Secp256k1Scalar {
    fn new_random() -> Secp256k1Scalar {
        let mut arr = [0u8; 32];

        let r = getrandom::getrandom(&mut arr[..]).unwrap();

        //thread_rng().fill(&mut arr[..]);
        Secp256k1Scalar {
            purpose: "random",
            fe: SK::parse_slice(&arr[0..arr.len()]).unwrap(),
        }
    }

    fn zero() -> Secp256k1Scalar {
        let zero_arr = [0u8; 32];
        let zero = unsafe { std::mem::transmute::<[u8; 32], SecretKey>(zero_arr) };
        Secp256k1Scalar {
            purpose: "zero",
            fe: zero,
        }
    }

    fn get_element(&self) -> SK {
        self.fe.clone()
    }

    fn set_element(&mut self, element: SK) {
        self.fe = element
    }

    fn from(n: &BigInt) -> Secp256k1Scalar {
        let curve_order = FE::q();
        let n_reduced = BigInt::mod_add(n, &BigInt::from(0 as u16), &curve_order);
        let mut v = BigInt::to_vec(&n_reduced);

        if v.len() < SECRET_KEY_SIZE {
            let mut template = vec![0; SECRET_KEY_SIZE - v.len()];
            template.extend_from_slice(&v);
            v = template;
        }

        Secp256k1Scalar {
            purpose: "from_big_int",
            fe: SK::parse_slice(&v).unwrap(),
        }
    }

    fn to_big_int(&self) -> BigInt {
        let fe_sc: Scalar = self.fe.clone().into();
        from(fe_sc.b32().as_ref())
    }

    fn q() -> BigInt {
        from(CURVE_ORDER.as_ref())
    }

    fn add(&self, other: &SK) -> Secp256k1Scalar {
        let mut other_scalar: FE = ECScalar::new_random();
        other_scalar.set_element(other.clone());
        let res: FE = ECScalar::from(&BigInt::mod_add(
            &self.to_big_int(),
            &other_scalar.to_big_int(),
            &FE::q(),
        ));
        Secp256k1Scalar {
            purpose: "add",
            fe: res.get_element(),
        }
    }

    fn mul(&self, other: &SK) -> Secp256k1Scalar {
        let mut other_scalar: FE = ECScalar::new_random();
        other_scalar.set_element(other.clone());
        let res: FE = ECScalar::from(&BigInt::mod_mul(
            &self.to_big_int(),
            &other_scalar.to_big_int(),
            &FE::q(),
        ));
        Secp256k1Scalar {
            purpose: "mul",
            fe: res.get_element(),
        }
    }

    fn sub(&self, other: &SK) -> Secp256k1Scalar {
        let mut other_scalar: FE = ECScalar::new_random();
        other_scalar.set_element(other.clone());
        let res: FE = ECScalar::from(&BigInt::mod_sub(
            &self.to_big_int(),
            &other_scalar.to_big_int(),
            &FE::q(),
        ));
        Secp256k1Scalar {
            purpose: "sub",
            fe: res.get_element(),
        }
    }

    fn invert(&self) -> Secp256k1Scalar {
        let bignum = self.to_big_int();
        let bn_inv = BigInt::mod_inv(&bignum, &FE::q());
        ECScalar::from(&bn_inv)
    }
}

impl Mul<Secp256k1Scalar> for Secp256k1Scalar {
    type Output = Secp256k1Scalar;
    fn mul(self, other: Secp256k1Scalar) -> Secp256k1Scalar {
        (&self).mul(&other.get_element())
    }
}

impl<'o> Mul<&'o Secp256k1Scalar> for Secp256k1Scalar {
    type Output = Secp256k1Scalar;
    fn mul(self, other: &'o Secp256k1Scalar) -> Secp256k1Scalar {
        (&self).mul(&other.get_element())
    }
}

impl Add<Secp256k1Scalar> for Secp256k1Scalar {
    type Output = Secp256k1Scalar;
    fn add(self, other: Secp256k1Scalar) -> Secp256k1Scalar {
        (&self).add(&other.get_element())
    }
}

impl<'o> Add<&'o Secp256k1Scalar> for Secp256k1Scalar {
    type Output = Secp256k1Scalar;
    fn add(self, other: &'o Secp256k1Scalar) -> Secp256k1Scalar {
        (&self).add(&other.get_element())
    }
}

impl Serialize for Secp256k1Scalar {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_big_int().to_hex())
    }
}

impl<'de> Deserialize<'de> for Secp256k1Scalar {
    fn deserialize<D>(deserializer: D) -> Result<Secp256k1Scalar, D::Error>
    where
        D: Deserializer<'de>,
    {
        deserializer.deserialize_str(Secp256k1ScalarVisitor)
    }
}

struct Secp256k1ScalarVisitor;

impl<'de> Visitor<'de> for Secp256k1ScalarVisitor {
    type Value = Secp256k1Scalar;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Secp256k1Scalar")
    }

    fn visit_str<E: de::Error>(self, s: &str) -> Result<Secp256k1Scalar, E> {
        let v = BigInt::from_str_radix(s, 16).expect("Failed in serde");
        Ok(ECScalar::from(&v))
    }
}

impl PartialEq for Secp256k1Scalar {
    fn eq(&self, other: &Secp256k1Scalar) -> bool {
        self.get_element() == other.get_element()
    }
}

impl PartialEq for Secp256k1Point {
    fn eq(&self, other: &Secp256k1Point) -> bool {
        self.get_element() == other.get_element()
    }
}

impl Zeroize for GE {
    fn zeroize(&mut self) {
        unsafe { ptr::write_volatile(self, GE::generator()) };
        atomic::fence(atomic::Ordering::SeqCst);
        atomic::compiler_fence(atomic::Ordering::SeqCst);
    }
}

impl ECPoint<PK, SK> for Secp256k1Point {
    fn generator() -> Secp256k1Point {
        let mut v = vec![4 as u8];
        v.extend(GENERATOR_X.as_ref());
        v.extend(GENERATOR_Y.as_ref());
        Secp256k1Point {
            purpose: "base_fe",
            ge: PK::parse_slice(&v, None).unwrap(),
        }
    }

    fn get_element(&self) -> PK {
        self.ge.clone()
    }

    /// to return from BigInt to PK use from_bytes:
    /// 1) convert BigInt::to_vec
    /// 2) remove first byte [1..33]
    /// 3) call from_bytes
    fn bytes_compressed_to_big_int(&self) -> BigInt {
        let mut serial = self.ge.serialize();
        let y_coor_last_byte = serial[64].clone();
        let y_coor_parity = (y_coor_last_byte << 7) >> 7;
        let mut compressed = vec![2 + y_coor_parity];
        compressed.append(&mut serial[1..33].to_vec());
        from(&compressed)
    }

    fn x_coor(&self) -> Option<BigInt> {
        let serialized_pk = PK::serialize(&self.ge);
        let x = &serialized_pk[1..serialized_pk.len() / 2 + 1];
        let x_vec = x.to_vec();
        Some(from(&x_vec[..]))
    }

    fn y_coor(&self) -> Option<BigInt> {
        let serialized_pk = PK::serialize(&self.ge);
        let y = &serialized_pk[(serialized_pk.len() - 1) / 2 + 1..serialized_pk.len()];
        let y_vec = y.to_vec();
        Some(from(&y_vec[..]))
    }

    fn from_bytes(bytes: &[u8]) -> Result<Secp256k1Point, ErrorKey> {
        let bytes_vec = bytes.to_vec();
        let mut bytes_array_65 = [0u8; 65];
        let mut bytes_array_33 = [0u8; 33];

        let byte_len = bytes_vec.len();
        match byte_len {
            33..=63 => {
                let mut template = vec![0; 64 - bytes_vec.len()];
                template.extend_from_slice(&bytes);
                let bytes_vec = template;
                let mut template: Vec<u8> = vec![4];
                template.append(&mut bytes_vec.clone());
                let bytes_slice = &template[..];

                bytes_array_65.copy_from_slice(&bytes_slice[0..65]);
                let result = PK::parse(&bytes_array_65);
                let test = result.map(|pk| Secp256k1Point {
                    purpose: "random",
                    ge: pk,
                });
                test.map_err(|_err| ErrorKey::InvalidPublicKey)
            }

            0..=32 => {
                let mut template = vec![0; 32 - bytes_vec.len()];
                template.extend_from_slice(&bytes);
                let bytes_vec = template;
                let mut rng = rand::thread_rng();
                let bit: bool = rng.gen();
                println!("rand {:?}", 2 + bit as u8);
                let mut template: Vec<u8> = vec![2 + bit as u8];
                template.append(&mut bytes_vec.clone());
                let bytes_slice = &template[..];

                bytes_array_33.copy_from_slice(&bytes_slice[0..33]);
                let result = PK::parse_compressed(&bytes_array_33);
                let test = result.map(|pk| Secp256k1Point {
                    purpose: "random",
                    ge: pk,
                });
                test.map_err(|_err| ErrorKey::InvalidPublicKey)
            }
            _ => {
                let bytes_slice = &bytes_vec[0..64];
                let bytes_vec = bytes_slice.to_vec();
                let mut template: Vec<u8> = vec![4];
                template.append(&mut bytes_vec.clone());
                let bytes_slice = &template[..];

                bytes_array_65.copy_from_slice(&bytes_slice[0..65]);
                let result = PK::parse(&bytes_array_65);
                let test = result.map(|pk| Secp256k1Point {
                    purpose: "random",
                    ge: pk,
                });
                test.map_err(|_err| ErrorKey::InvalidPublicKey)
            }
        }
    }
    fn pk_to_key_slice(&self) -> Vec<u8> {
        let mut v = vec![4 as u8];

        v.extend(BigInt::to_vec(&self.x_coor().unwrap()));
        v.extend(BigInt::to_vec(&self.y_coor().unwrap()));
        v
    }

    fn scalar_mul(&self, fe: &SK) -> Secp256k1Point {
        let mut new_point = self.clone();
        new_point
            .ge
            //.tweak_mul_assign_with_context(fe, context)
            .tweak_mul_assign(fe)
            .expect("Assignment expected");
        new_point
    }

    fn add_point(&self, other: &PK) -> Secp256k1Point {
        Secp256k1Point {
            purpose: "combine",
            ge: PublicKey::combine(&[self.ge.clone(), other.clone()]).unwrap(),
        }
    }

    fn sub_point(&self, other: &PK) -> Secp256k1Point {
        let point = Secp256k1Point {
            purpose: "sub_point",
            ge: other.clone(),
        };
        let p: Vec<u8> = vec![
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
            255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 254, 255, 255, 252, 47,
        ];
        let order = from(&p[..]);
        let x = point.x_coor().unwrap();
        let y = point.y_coor().unwrap();
        let minus_y = BigInt::mod_sub(&order, &y, &order);

        let x_vec = BigInt::to_vec(&x);
        let y_vec = BigInt::to_vec(&minus_y);

        let mut template_x = vec![0; 32 - x_vec.len()];
        template_x.extend_from_slice(&x_vec);
        let mut x_vec = template_x;

        let mut template_y = vec![0; 32 - y_vec.len()];
        template_y.extend_from_slice(&y_vec);
        let y_vec = template_y;

        x_vec.extend_from_slice(&y_vec);

        let minus_point: GE = ECPoint::from_bytes(&x_vec).unwrap();
        //let minus_point: GE = ECPoint::from_coor(&x, &y_inv);
        ECPoint::add_point(self, &minus_point.get_element())
    }

    fn from_coor(x: &BigInt, y: &BigInt) -> Secp256k1Point {
        let mut vec_x = BigInt::to_vec(x);
        let mut vec_y = BigInt::to_vec(y);
        let coor_size = (UNCOMPRESSED_PUBLIC_KEY_SIZE - 1) / 2;

        if vec_x.len() < coor_size {
            // pad
            let mut x_buffer = vec![0; coor_size - vec_x.len()];
            x_buffer.extend_from_slice(&vec_x);
            vec_x = x_buffer
        }

        if vec_y.len() < coor_size {
            // pad
            let mut y_buffer = vec![0; coor_size - vec_y.len()];
            y_buffer.extend_from_slice(&vec_y);
            vec_y = y_buffer
        }

        assert_eq!(x, &from(vec_x.as_ref()));
        assert_eq!(y, &from(vec_y.as_ref()));

        let mut v = vec![4 as u8];
        v.extend(vec_x);
        v.extend(vec_y);

        Secp256k1Point {
            purpose: "base_fe",
            ge: PK::parse_slice(&v, None).unwrap(),
        }
    }
}

impl Mul<Secp256k1Scalar> for Secp256k1Point {
    type Output = Secp256k1Point;
    fn mul(self, other: Secp256k1Scalar) -> Self::Output {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o Secp256k1Scalar> for Secp256k1Point {
    type Output = Secp256k1Point;
    fn mul(self, other: &'o Secp256k1Scalar) -> Self::Output {
        self.scalar_mul(&other.get_element())
    }
}

impl<'o> Mul<&'o Secp256k1Scalar> for &'o Secp256k1Point {
    type Output = Secp256k1Point;
    fn mul(self, other: &'o Secp256k1Scalar) -> Self::Output {
        self.scalar_mul(&other.get_element())
    }
}

impl Add<Secp256k1Point> for Secp256k1Point {
    type Output = Secp256k1Point;
    fn add(self, other: Secp256k1Point) -> Self::Output {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o Secp256k1Point> for Secp256k1Point {
    type Output = Secp256k1Point;
    fn add(self, other: &'o Secp256k1Point) -> Self::Output {
        self.add_point(&other.get_element())
    }
}

impl<'o> Add<&'o Secp256k1Point> for &'o Secp256k1Point {
    type Output = Secp256k1Point;
    fn add(self, other: &'o Secp256k1Point) -> Self::Output {
        self.add_point(&other.get_element())
    }
}

impl Serialize for Secp256k1Point {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Secp256k1Point", 2)?;
        state.serialize_field("x", &self.x_coor().unwrap().to_hex())?;
        state.serialize_field("y", &self.y_coor().unwrap().to_hex())?;
        state.end()
    }
}

impl<'de> Deserialize<'de> for Secp256k1Point {
    fn deserialize<D>(deserializer: D) -> Result<Secp256k1Point, D::Error>
    where
        D: Deserializer<'de>,
    {
        let fields = &["x", "y"];
        deserializer.deserialize_struct("Secp256k1Point", fields, Secp256k1PointVisitor)
    }
}

struct Secp256k1PointVisitor;

impl<'de> Visitor<'de> for Secp256k1PointVisitor {
    type Value = Secp256k1Point;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("Secp256k1Point")
    }

    fn visit_map<E: MapAccess<'de>>(self, mut map: E) -> Result<Secp256k1Point, E::Error> {
        let mut x = String::new();
        let mut y = String::new();

        while let Some(ref key) = map.next_key::<String>()? {
            let v = map.next_value::<String>()?;
            if key == "x" {
                x = v
            } else if key == "y" {
                y = v
            } else {
                panic!("Serialization failed!")
            }
        }

        let bx = BigInt::from_hex(&x);
        let by = BigInt::from_hex(&y);

        Ok(Secp256k1Point::from_coor(&bx, &by))
    }
}
