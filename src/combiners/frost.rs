use std::fmt::Debug;

use frost_core::{
    aggregate,
    keys::{PublicKeyPackage, VerifyingShare},
    round1::{NonceCommitment, SigningCommitments},
    round2::SignatureShare,
    serialization::ScalarSerialization,
    Ciphersuite, Field, Group, Identifier, Signature, SigningPackage, VerifyingKey,
};
use serde::{Deserialize, Serialize};

#[derive(Deserialize)]
#[serde(bound = "")]
struct SigShareInput<C: Ciphersuite> {
    sig_type: String,
    data_signed: String,
    public_key: VerifyingKey<C>,
    share_index: Identifier<C>,
    verifying_share: VerifyingShare<C>,
    hiding_nonce: NonceCommitment<C>,
    binding_nonce: NonceCommitment<C>,
    signature_share: String,
    sig_name: String,
}

pub fn combine_signature<'de, C: Ciphersuite>(shares: Vec<String>) -> String {
    let shares = shares
        .into_iter()
        .map(|share| serde_json::from_str::<SigShareInput<C>>(&share).unwrap())
        .collect::<Vec<_>>();

    let message = hex::decode(&shares.first().unwrap().data_signed).unwrap();

    let signing_package = SigningPackage::new(
        shares
            .iter()
            .map(|share| {
                (
                    share.share_index,
                    SigningCommitments::new(share.hiding_nonce, share.binding_nonce),
                )
            })
            .collect(),
        &message,
    );

    let signature = aggregate::<C>(
        &signing_package,
        &shares
            .iter()
            .map(|share| {
                (
                    share.share_index,
                    SignatureShare::deserialize(
                        <<C::Group as Group>::Field as Field>::Serialization::try_from(
                            hex::decode(&share.signature_share).unwrap(),
                        )
                        .map_err(|_| "cannot deserialize")
                        .unwrap(),
                    )
                    .unwrap(),
                )
            })
            .collect(),
        &PublicKeyPackage::new(
            shares
                .iter()
                .map(|share| (share.share_index, share.verifying_share))
                .collect(),
            shares.first().unwrap().public_key.clone(),
        ),
    )
    .unwrap();

    serde_json::to_string(&signature).unwrap()
}
