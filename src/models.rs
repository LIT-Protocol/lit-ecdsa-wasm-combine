pub enum KeyType {
    Undefined = 0,
    BLS = 1,
    EcdsaZg = 2,
    EcdsaCaitSithK256 = 3,
    EcdsaCaitSithP256 = 4,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignatureRecidHex {
    pub r: String,
    pub s: String,
    pub recid: u8,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SignedData {
    pub sig_type: String,
    pub data_signed: String,
    pub signature_share: String,
    pub share_index: u32,
    pub local_x: String,
    pub local_y: String,
    pub public_key: String,
    pub sig_name: String,
}

#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct SignedDatak256 {
    pub sig_type: String,
    pub data_signed: k256::Scalar,
    pub signature_share: k256::Scalar,
    pub share_index: u32,
    pub local_x: k256::AffinePoint,
    pub local_y: k256::AffinePoint,
    pub public_key: k256::AffinePoint,
    pub sig_name: String,
}
