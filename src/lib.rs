

pub use secp256k1;

#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

pub mod address;
pub mod bech32;
pub mod bip32;
pub mod bip39;
pub mod script;
pub mod sighash;
pub mod sign;
pub mod tx;

use sha2::{Digest, Sha256};

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}


pub fn sha256d(data: &[u8]) -> [u8; 32] {
    sha256(&sha256(data))
}

pub fn hash160(data: &[u8]) -> [u8; 20] {
    ripemd::Ripemd160::digest(Sha256::digest(data)).into()
}

pub fn tagged_hash(tag: &str, data: &[u8]) -> [u8; 32] {
    let tag = sha256(tag.as_bytes());
    let mut hasher = Sha256::new();
    hasher.update(tag);
    hasher.update(tag);
    hasher.update(data);
    hasher.finalize().into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_hashes_are_the_standard_ones() {
        assert_eq!(
            hex::encode(sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex::encode(sha256d(b"abc")),
            "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358"
        );
        let key = hex::decode("0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798").unwrap();
        assert_eq!(hex::encode(hash160(&key)), "751e76e8199196d454941c45d1b3a323f1433bd6");
    }

    #[test]
    fn a_tagged_hash_prefixes_the_tag_hash_twice() {
        let tag = sha256(b"TapTweak");
        let mut by_hand = Vec::new();
        by_hand.extend(tag);
        by_hand.extend(tag);
        by_hand.extend([7u8; 32]);
        assert_eq!(tagged_hash("TapTweak", &[7u8; 32]), sha256(&by_hand));
    }
}
