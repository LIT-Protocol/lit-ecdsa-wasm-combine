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
    const id: &str = "hello-world";
    const public_keys: [&str; 2] = ["049552b1bec13fb7903b052d5ea7cbe0227f3b2d01e131aa04caaab61cddc9e53840e4959ec2388e6f332e089399ccbe515464034ed999ada56a6a449822ce8285", "046b47116d2edea42e526274a468fc80f94f509ab9797763bd80d879a048ab4cb4348cca96489ddabdb978ddb06487897d9f983d047e23788153f7a535d8d7d7ff"];

    let mut hd_pub_keys = Vec::with_capacity(public_keys.len() as usize);
    for pubkey in public_keys.iter() {
        let hex_pub_key = hex::decode(pubkey).unwrap();
        let a_p = convert_to_point(hex_pub_key.as_slice());
        hd_pub_keys.push(a_p);
    }
    let deriver =
        combiners::hd_ecdsa::HdKeyDeriver::<Secp256k1>::new(id.as_bytes(), combiners::hd_ecdsa::CXT).unwrap();

    let pubkey = deriver.compute_public_key(&hd_pub_keys.as_slice());
    let pubkey = hex::encode(pubkey.to_encoded_point(true).as_bytes());
    
    println!("pubkey {}", pubkey);
}