

use std::fmt;
use std::str::FromStr;

use secp256k1::{PublicKey, XOnlyPublicKey};

use crate::{bech32, hash160, script, sign};

const HRP: &str = "bc";
const P2PKH_VERSION: u8 = 0x00;
const P2SH_VERSION: u8 = 0x05;

/// What an address pays to.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Payload {
    PubkeyHash([u8; 20]),
    ScriptHash([u8; 20]),
    Witness { version: u8, program: Vec<u8> },
}

/// A mainnet address.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Address(Payload);

/// The script type behind an address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    P2pkh,
    P2sh,
    P2wpkh,
    P2wsh,
    P2tr,
    OtherWitness,
}

impl Address {

    pub fn parse(s: &str) -> Result<Address, String> {
        if s.get(..3).is_some_and(|prefix| prefix.eq_ignore_ascii_case("bc1")) {
            let (version, program) = bech32::segwit_decode(HRP, s)?;
            return Ok(Address(Payload::Witness { version, program }));
        }
        let bytes = bs58::decode(s)
            .with_check(None)
            .into_vec()
            .map_err(|_| "not a Bitcoin address".to_string())?;
        if bytes.len() != 21 {
            return Err("not a Bitcoin address".to_string());
        }
        let mut hash = [0u8; 20];
        hash.copy_from_slice(&bytes[1..]);
        match bytes[0] {
            P2PKH_VERSION => Ok(Address(Payload::PubkeyHash(hash))),
            P2SH_VERSION => Ok(Address(Payload::ScriptHash(hash))),
            _ => Err("not a mainnet address".to_string()),
        }
    }


    pub fn from_script(script: &[u8]) -> Option<Address> {
        match script {
            [script::OP_DUP, script::OP_HASH160, 20, hash @ .., script::OP_EQUALVERIFY, script::OP_CHECKSIG]
                if hash.len() == 20 =>
            {
                Some(Address(Payload::PubkeyHash(hash.try_into().ok()?)))
            }
            [script::OP_HASH160, 20, hash @ .., script::OP_EQUAL] if hash.len() == 20 => {
                Some(Address(Payload::ScriptHash(hash.try_into().ok()?)))
            }
            [op, len, program @ ..] if *len as usize == program.len() && (2..=40).contains(&program.len()) => {
                let version = match *op {
                    script::OP_0 => 0,
                    script::OP_1..=script::OP_16 => op - script::OP_1 + 1,
                    _ => return None,
                };
                if version == 0 && program.len() != 20 && program.len() != 32 {
                    return None;
                }
                Some(Address(Payload::Witness { version, program: program.to_vec() }))
            }
            _ => None,
        }
    }

    /// The output script that pays this address.
    pub fn script_pubkey(&self) -> Vec<u8> {
        match &self.0 {
            Payload::PubkeyHash(hash) => script::p2pkh(hash),
            Payload::ScriptHash(hash) => script::p2sh(hash),
            Payload::Witness { version, program } => script::witness(*version, program),
        }
    }

    pub fn kind(&self) -> Kind {
        match &self.0 {
            Payload::PubkeyHash(_) => Kind::P2pkh,
            Payload::ScriptHash(_) => Kind::P2sh,
            Payload::Witness { version: 0, program } if program.len() == 20 => Kind::P2wpkh,
            Payload::Witness { version: 0, .. } => Kind::P2wsh,
            Payload::Witness { version: 1, program } if program.len() == 32 => Kind::P2tr,
            Payload::Witness { .. } => Kind::OtherWitness,
        }
    }

    /// `1…`: pay to the hash of the key.
    pub fn p2pkh(key: &PublicKey) -> Address {
        Address(Payload::PubkeyHash(hash160(&key.serialize())))
    }

    /// `3…`: pay to the hash of the key's P2WPKH script (BIP-49).
    pub fn p2sh_p2wpkh(key: &PublicKey) -> Address {
        Address(Payload::ScriptHash(hash160(&script::p2wpkh(&hash160(&key.serialize())))))
    }

    /// `bc1q…`: witness version 0, the hash of the key (BIP-84).
    pub fn p2wpkh(key: &PublicKey) -> Address {
        Address(Payload::Witness { version: 0, program: hash160(&key.serialize()).to_vec() })
    }

    /// `bc1p…`: witness version 1, the key tweaked with no script tree
    /// (BIP-86).
    pub fn p2tr(internal: &XOnlyPublicKey) -> Address {
        Address(Payload::Witness { version: 1, program: sign::tweaked_output_key(internal).to_byte_array().to_vec() })
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.0 {
            Payload::PubkeyHash(hash) => f.write_str(&base58check(P2PKH_VERSION, hash)),
            Payload::ScriptHash(hash) => f.write_str(&base58check(P2SH_VERSION, hash)),
            Payload::Witness { version, program } => f.write_str(
                &bech32::segwit_encode(HRP, *version, program).expect("every payload was checked when it was made"),
            ),
        }
    }
}

impl FromStr for Address {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        Address::parse(s)
    }
}

fn base58check(version: u8, hash: &[u8; 20]) -> String {
    let mut bytes = Vec::with_capacity(21);
    bytes.push(version);
    bytes.extend_from_slice(hash);
    bs58::encode(bytes).with_check().into_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    
    const PARSED: &[(&str, Option<(&str, &str)>)] = &[
        ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", Some(("0014751e76e8199196d454941c45d1b3a323f1433bd6", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"))),
        ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", Some(("0014751e76e8199196d454941c45d1b3a323f1433bd6", "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"))),
        ("bc1Qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", None),
        ("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3", Some(("00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262", "bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"))),
        ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", Some(("512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798", "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"))),
        ("bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr", Some(("5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c", "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"))),
        ("BC1SW50QGDZ25J", Some(("6002751e", "bc1sw50qgdz25j"))),
        ("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", Some(("5210751e76e8199196d454941c45d1b3a323", "bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs"))),
        ("bc1sw50qgdz25j", Some(("6002751e", "bc1sw50qgdz25j"))),
        ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", None),
        ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", None),
        ("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4 ", None),
        ("tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx", None),
        ("bc1q", None),
        ("1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA", Some(("76a914d986ed01b7a22225a70edbf2ba7cfb63a15cb3aa88ac", "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"))),
        ("1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabB", None),
        ("37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf", Some(("a9143fb6e95812e57bb4691f9a4a628862a61a4f769b87", "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"))),
        ("mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn", None),
        ("2MzQwSSnBHWHqSAqtTVQ6v47XtaisrJa1Vc", None),
        ("bc1qyfxmsjaaaaaaaaaaaaaaaaaaaaaaaaaaamh06f67", None),
        ("", None),
        ("not an address", None),
        ("1", None),
        ("bc1", None),
    ];

    #[test]
    fn parsing_matches_the_wallet_before_this_crate() {
        for (s, expected) in PARSED {
            match (Address::parse(s), expected) {
                (Ok(a), Some((script, display))) => {
                    assert_eq!(hex::encode(a.script_pubkey()), *script, "{s}");
                    assert_eq!(a.to_string(), *display, "{s}");
                    assert_eq!(Address::from_script(&a.script_pubkey()), Some(a), "{s}");
                }
                (Err(_), None) => {}
                (r, _) => panic!("{s}: {r:?}"),
            }
        }
    }

    #[test]
    fn the_bip350_mainnet_vectors_parse_and_the_invalid_ones_do_not() {
        for (address, script) in bech32::tests::VALID_ADDRESSES {
            if address.to_ascii_lowercase().starts_with("bc") {
                let a = Address::parse(address).unwrap();
                assert_eq!(hex::encode(a.script_pubkey()), *script, "{address}");
            } else {
                assert!(Address::parse(address).is_err(), "{address} is not mainnet");
            }
        }
        for address in bech32::tests::INVALID_ADDRESSES {
            assert!(Address::parse(address).is_err(), "{address}");
        }
    }

    #[test]
    fn kinds() {
        let kind = |s: &str| Address::parse(s).unwrap().kind();
        assert_eq!(kind("1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"), Kind::P2pkh);
        assert_eq!(kind("37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"), Kind::P2sh);
        assert_eq!(kind("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4"), Kind::P2wpkh);
        assert_eq!(kind("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3"), Kind::P2wsh);
        assert_eq!(kind("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0"), Kind::P2tr);
        assert_eq!(kind("bc1sw50qgdz25j"), Kind::OtherWitness);
        assert_eq!(kind("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs"), Kind::OtherWitness);
        assert_eq!(kind("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y"), Kind::OtherWitness);
    }

    /// The first address of each type from the `abandon … about` seed: the
    /// vectors BIP-84 and BIP-86 publish, and the ones the reference
    /// implementations give for BIP-44 and BIP-49.
    #[test]
    fn the_four_types_from_a_key() {
        let key = |hex: &str| PublicKey::from_slice(&hex::decode(hex).unwrap()).unwrap();
        assert_eq!(
            Address::p2wpkh(&key("0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c")).to_string(),
            "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
        );
        let (internal, _) = key("03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115").x_only_public_key();
        assert_eq!(
            Address::p2tr(&internal).to_string(),
            "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr"
        );
        assert_eq!(
            Address::p2sh_p2wpkh(&key("039b3b694b8fc5b5e07fb069c783cac754f5d38c3e08bed1960e31fdb1dda35c24")).to_string(),
            "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf"
        );
        assert_eq!(
            Address::p2pkh(&key("03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e")).to_string(),
            "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
        );
    }

    /// BIP-341's key-path-only output: the internal key, its tweak, the
    /// output script and the address.
    #[test]
    fn the_bip341_key_path_output() {
        let internal = XOnlyPublicKey::from_byte_array(
            hex::decode("d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d").unwrap().try_into().unwrap(),
        )
        .unwrap();
        let a = Address::p2tr(&internal);
        assert_eq!(
            hex::encode(a.script_pubkey()),
            "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"
        );
        assert_eq!(a.to_string(), "bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5");
    }

    #[test]
    fn scripts_without_an_address() {
        for script in [
            "2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac", // P2PK
            "6a0b68656c6c6f20776f726c64",                                                     // OP_RETURN
            "0014751e76e8199196d454941c45d1b3a323f1433bd600",                                 // trailing byte
            "0013751e76e8199196d454941c45d1b3a323f1433b",                                     // 19-byte v0
            "5101ff",                                                                         // 1-byte v1
            "",
        ] {
            assert_eq!(Address::from_script(&hex::decode(script).unwrap()), None, "{script}");
        }
    }
}
