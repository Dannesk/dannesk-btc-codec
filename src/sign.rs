

use secp256k1::{Keypair, Message, Scalar, SecretKey, XOnlyPublicKey, schnorr};

use crate::{sighash, tagged_hash};

pub fn ecdsa_sighash_all(digest: &[u8; 32], secret: &SecretKey) -> Vec<u8> {
    let signature = secret.sign_ecdsa(Message::from_digest(*digest));
    let mut bytes = signature.serialize_der().to_vec();
    bytes.push(sighash::SIGHASH_ALL);
    bytes
}

pub fn taproot_tweak(internal: &XOnlyPublicKey, merkle_root: Option<&[u8; 32]>) -> Scalar {
    let mut data = Vec::with_capacity(64);
    data.extend_from_slice(&internal.to_byte_array());
    if let Some(root) = merkle_root {
        data.extend_from_slice(root);
    }
    Scalar::from_be_bytes(tagged_hash("TapTweak", &data)).expect("a hash is a scalar")
}


pub fn tweaked_output_key(internal: &XOnlyPublicKey) -> XOnlyPublicKey {
    internal.add_tweak(&taproot_tweak(internal, None)).expect("a tweaked key is a point").0
}


pub fn tweaked_keypair(secret: &SecretKey, merkle_root: Option<&[u8; 32]>) -> Keypair {
    let keypair = secret.keypair();
    let (internal, _) = keypair.x_only_public_key();
    keypair.add_xonly_tweak(&taproot_tweak(&internal, merkle_root)).expect("a tweaked key is a point")
}


pub fn schnorr_key_spend(digest: &[u8; 32], secret: &SecretKey, aux_rand: &[u8; 32]) -> [u8; 64] {
    schnorr::sign_with_aux_rand(digest, &tweaked_keypair(secret, None), aux_rand).to_byte_array()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_wallets_taproot_key_tweaks_and_signs_the_same() {
        let secret = SecretKey::from_secret_bytes(
            hex::decode("41f41d69260df4cf277826a9b65a3717e4eeddbeedf637f212ca096576479361").unwrap().try_into().unwrap(),
        )
        .unwrap();
        let (internal, _) = secret.x_only_public_key();
        assert_eq!(hex::encode(internal.to_byte_array()), "cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115");
        assert_eq!(
            hex::encode(tweaked_output_key(&internal).to_byte_array()),
            "a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
        );
        let keypair = tweaked_keypair(&secret, None);
        assert_eq!(
            hex::encode(keypair.to_secret_bytes()),
            "eaac016f36e8c18347fbacf05ab7966708fbfce7ce3bf1dc32a09dd0645db038"
        );
        let digest: [u8; 32] =
            hex::decode("dc1eaa3584a92fbb8ca0e7378b996561a4f13d117bbad7479b173228fc0a73e7").unwrap().try_into().unwrap();
        assert_eq!(
            hex::encode(schnorr_key_spend(&digest, &secret, &[0u8; 32])),
            "01cd1e375030830678fce7fafd63243a462548d36c06c05b38978c75ab1e53f06e4083976711d082281116a9d733e2326731c8846275520c459dfae2c9acc8bf"
        );
        let other = schnorr_key_spend(&digest, &secret, &[1u8; 32]);
        assert_ne!(other, schnorr_key_spend(&digest, &secret, &[0u8; 32]));
        let sig = schnorr::Signature::from_byte_array(other);
        assert!(sig.verify(&digest, &tweaked_output_key(&internal)).is_ok());
    }

    #[test]
    fn ecdsa_is_deterministic_and_carries_the_hash_type() {
        let secret = SecretKey::from_secret_bytes(
            hex::decode("e284129cc0922579a535bbf4d1a3b25773090d28c909bc0fed73b5e0222cc372").unwrap().try_into().unwrap(),
        )
        .unwrap();
        let digest: [u8; 32] =
            hex::decode("280e533c81ee6651c143d1b5606de0743f1c5a6c98462128b1d05eae6bdac96c").unwrap().try_into().unwrap();
        let sig = ecdsa_sighash_all(&digest, &secret);
        assert_eq!(
            hex::encode(&sig),
            "3044022076e3772f3ad10c012e557de5f9484746a1c5678edad4efd1bc121652a1a92d230220691d389995b38a8cde0076db8330ce6637e8ca5b2702095262d75d3a952f06b901"
        );
        let der = secp256k1::ecdsa::Signature::from_der(&sig[..sig.len() - 1]).unwrap();
        let mut low_s = der;
        low_s.normalize_s();
        assert_eq!(low_s, der);
        assert!(der.verify(Message::from_digest(digest), &secret.public_key()).is_ok());
    }
}
