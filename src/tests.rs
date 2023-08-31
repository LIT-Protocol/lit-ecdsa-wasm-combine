use elliptic_curve::sec1::ToEncodedPoint;
use k256::Secp256k1;

#[cfg(test)]
use crate::combiners;
use crate::convert_to_point;

#[test]
pub fn cait_sith_test_k256() {
    let share1 = "{ \"sig_type\": \"EcdsaCaitSith\", \"data_signed\": \"A591A6D40BF420404A011733CFB7B190D62C65BF0BCDA32B57B277D9AD9F146E\", \"signature_share\": \"01C4E0EDD498B14DFE8D87163C39F738B8AC17172B55A6A9518E3704362B4FC1\", \"share_index\": 0, \"local_x\": \"0203899AD2B6B56D65130DDAE01A099D867FDC5DF9219CD1B31A48B03FA0AF05EA\", \"local_y\": \"0203899AD2B6B56D65130DDAE01A099D867FDC5DF9219CD1B31A48B03FA0AF05EA\", \"public_key\": \"03D589E6B6FF8B611D073F6161E8A8D9A9A737C6B102D284984ACE0F0326073402\", \"sig_name\": \"sig1\" }";
    let share2 = "{ \"sig_type\": \"EcdsaCaitSith\", \"data_signed\": \"A591A6D40BF420404A011733CFB7B190D62C65BF0BCDA32B57B277D9AD9F146E\", \"signature_share\": \"FE3B1F122B674EB2017278E9C3C608C60202C5CF83F2F9926E4427889A0AF180\", \"share_index\": 0, \"local_x\": \"0203899AD2B6B56D65130DDAE01A099D867FDC5DF9219CD1B31A48B03FA0AF05EA\", \"local_y\": \"0203899AD2B6B56D65130DDAE01A099D867FDC5DF9219CD1B31A48B03FA0AF05EA\", \"public_key\": \"03D589E6B6FF8B611D073F6161E8A8D9A9A737C6B102D284984ACE0F0326073402\", \"sig_name\": \"sig1\" }";
    let share3 = "{ \"sig_type\": \"EcdsaCaitSith\", \"data_signed\": \"A591A6D40BF420404A011733CFB7B190D62C65BF0BCDA32B57B277D9AD9F146E\", \"signature_share\": \"55EC4AF9F1883B19FF84825CBEBDFD127BC8FBFF48DF6CF705CADC85ACCB3056\", \"share_index\": 0, \"local_x\": \"0203899AD2B6B56D65130DDAE01A099D867FDC5DF9219CD1B31A48B03FA0AF05EA\", \"local_y\": \"0203899AD2B6B56D65130DDAE01A099D867FDC5DF9219CD1B31A48B03FA0AF05EA\", \"public_key\": \"03D589E6B6FF8B611D073F6161E8A8D9A9A737C6B102D284984ACE0F0326073402\", \"sig_name\": \"sig1\" }";

    let mut shares = Vec::new();
    shares.push(share1.to_string());
    shares.push(share2.to_string());
    shares.push(share3.to_string());

    combiners::k256_cait_sith::combine_signature(shares);
}

#[test]
pub fn hd_key_compute_pub_key() {
    const id: &str = "d856c933322bb32c0f055522c68fc8ffd7bed30c41fffd4e2c4562c28894a7c0";
    const public_keys: [&str; 10] = [
        "040416ff2418dbd58b05a99b7b8fa0f090d6c24ecc6964fef4239ef151db163f024b7da356854844c1b46556ed5ffcb4f8f11a169bbf33121aa18e29dc76b99843",
        "04504f9e8ddaf44a34e0aaed868b938cc1e7d5c3d3e1576581cd81650f5efa63c7694da0503f00711f347e62e06e78bf68674d75a668ca5a3c0f63422ed0869117",
        "04dcb77cea0bed0f619423254369228ff4f8b858a83eda1292183783cf376b4e43803dac382c56b84679789726734da92c54091c4cbcc4aebe83d9d0114ebe9c30",
        "040c50ac90bfd40319ec55d249298be693125991a5fd5007e44ab110fd79ec4f4c0b66051b85934a778059af2e091b9f291643510bc8889a1ea6e61f2766114b96",
        "0466c80a363c8888611a3e2c5af737693aae7150462b1d3a9efeb45c3704233f3427200762d2aa06810553e5d3495e3d84803eac2555078cefc34abb5007b63e9e",
        "04988e9d83be771461988fe8f6d787102e139547086fbf316f81e97d688e5da5983ad24260a1d730d288cd4281826ddb50ba053be513fbf1776593856b2b142b44",
        "0412c6bb58d88f64b922c7460214029feaaa4a0190234636f483c44d8135e99c65683f9a989a376b34ba61a496c2b8581f2ad7f9c22ece3b9405663798cb76eae2",
        "04bf4b5de0b17b4855bdc65a7594f16a2fc3fb2df837f63fb750e1bde06e6016df338207e922b0ca27f84525dc92190b3d912ce655289929618dd2933bc71ad7a6",
        "04d037c42f8d4bbf7d3aad9fdf92bcbb3e6fd1fef723ddee50668123b2464381701faf86fbba8742a272f319ea0781af5093d02da153f8f09546e2a921a30482e1",
        "0443c902f5aa2a845bc11caa0f69bb74ee06a9ebabbb0ce4473616987045296ec621c36351bf6e4075bea08fdbbbe93e6de071768f8df9f6452cf54e15109a4aee",
      ];

    let mut hd_pub_keys = Vec::with_capacity(public_keys.len() as usize);
    for pubkey in public_keys.iter() {
        let hex_pub_key = hex::decode(pubkey).unwrap();
        let a_p = convert_to_point(hex_pub_key.as_slice());
        hd_pub_keys.push(a_p);
    }
    let deriver = combiners::hd_ecdsa::HdKeyDeriver::<Secp256k1>::new(
        id.as_bytes(),
        combiners::hd_ecdsa::CXT,
    )
    .unwrap();

    let pubkey = deriver.compute_public_key(&hd_pub_keys.as_slice());
    println!(
        "public key bytes {:?} length {}",
        pubkey.to_encoded_point(false).as_bytes(),
        pubkey.to_encoded_point(false).as_bytes().len()
    );
    let pubkey = hex::encode(pubkey.to_encoded_point(false).as_bytes());

    println!("pubkey {}", pubkey);
}
