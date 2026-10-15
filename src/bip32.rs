

use std::fmt;
use std::str::FromStr;

use hmac::{Hmac, KeyInit, Mac};
use secp256k1::{PublicKey, Scalar, SecretKey};
use sha2::Sha512;
use zeroize::Zeroizing;

use crate::hash160;

pub const HARDENED: u32 = 0x8000_0000;

const XPRV_VERSION: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];
const XPUB_VERSION: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];

#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct DerivationPath(Vec<u32>);

impl DerivationPath {
    pub fn master() -> Self {
        Self(Vec::new())
    }

    pub fn from_indices(indices: Vec<u32>) -> Self {
        Self(indices)
    }

    pub fn indices(&self) -> &[u32] {
        &self.0
    }

    pub fn child(&self, index: u32) -> Result<Self, String> {
        if index >= HARDENED {
            return Err(format!("index {index} is out of range"));
        }
        let mut indices = self.0.clone();
        indices.push(index);
        Ok(Self(indices))
    }
}

impl FromStr for DerivationPath {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let mut parts = s.split('/');
        if parts.next() != Some("m") {
            return Err("a path starts with m".to_string());
        }
        let mut indices = Vec::new();
        for part in parts {
            let (digits, hardened) = match part.strip_suffix(['\'', 'h', 'H']) {
                Some(d) => (d, true),
                None => (part, false),
            };
            if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return Err(format!("'{part}' is not an index"));
            }
            let index: u32 = digits.parse().map_err(|_| format!("'{part}' is out of range"))?;
            if index >= HARDENED {
                return Err(format!("'{part}' is out of range"));
            }
            indices.push(if hardened { index | HARDENED } else { index });
        }
        Ok(Self(indices))
    }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("m")?;
        for &index in &self.0 {
            if index & HARDENED != 0 {
                write!(f, "/{}'", index & !HARDENED)?;
            } else {
                write!(f, "/{index}")?;
            }
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct Xpriv {
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
    chain_code: Zeroizing<[u8; 32]>,
    key: SecretKey,
}

impl Drop for Xpriv {
    fn drop(&mut self) {
      
        self.key.non_secure_erase();
    }
}

impl fmt::Debug for Xpriv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Xpriv(depth {}, child {})", self.depth, self.child_number)
    }
}

impl Xpriv {

    pub fn new_master(seed: &[u8]) -> Result<Xpriv, String> {
        if !(16..=64).contains(&seed.len()) {
            return Err(format!("a seed is 16 to 64 bytes, not {}", seed.len()));
        }
        let i = hmac_sha512(b"Bitcoin seed", seed);
        let key = SecretKey::from_secret_bytes(left(&i)).map_err(|_| "the seed gives no valid key".to_string())?;
        Ok(Xpriv {
            depth: 0,
            parent_fingerprint: [0; 4],
            child_number: 0,
            chain_code: Zeroizing::new(right(&i)),
            key,
        })
    }

    pub fn derive(&self, path: &DerivationPath) -> Result<Xpriv, String> {
        let mut key = self.clone();
        for &index in path.indices() {
            key = key.child(index)?;
        }
        Ok(key)
    }

    pub fn child(&self, index: u32) -> Result<Xpriv, String> {
        if self.depth == u8::MAX {
            return Err("the tree is 255 levels deep".to_string());
        }
        let mut data: Zeroizing<Vec<u8>> = Zeroizing::new(Vec::with_capacity(37));
        if index & HARDENED != 0 {
            data.push(0);
            data.extend_from_slice(&self.key.to_secret_bytes());
        } else {
            data.extend_from_slice(&self.public_key().serialize());
        }
        data.extend_from_slice(&index.to_be_bytes());
        let i = hmac_sha512(&*self.chain_code, &data);
     
        let tweak = Scalar::from_be_bytes(left(&i))
            .map_err(|_| format!("index {index} derives no valid key; use the next"))?;
        let key = self
            .key
            .add_tweak(&tweak)
            .map_err(|_| format!("index {index} derives no valid key; use the next"))?;
        Ok(Xpriv {
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: index,
            chain_code: Zeroizing::new(right(&i)),
            key,
        })
    }

    pub fn secret_key(&self) -> &SecretKey {
        &self.key
    }

    pub fn public_key(&self) -> PublicKey {
        self.key.public_key()
    }

    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    /// The first four bytes of hash160 of the public key: how a child names
    /// its parent.
    pub fn fingerprint(&self) -> [u8; 4] {
        fingerprint(&self.public_key())
    }

    /// The same key without its secret.
    pub fn to_xpub(&self) -> Xpub {
        Xpub {
            depth: self.depth,
            parent_fingerprint: self.parent_fingerprint,
            child_number: self.child_number,
            chain_code: *self.chain_code,
            key: self.public_key(),
        }
    }
}

impl fmt::Display for Xpriv {
    /// The `xprv…` string.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut key = Zeroizing::new([0u8; 33]);
        key[1..].copy_from_slice(&self.key.to_secret_bytes());
        let s = Zeroizing::new(encode(
            XPRV_VERSION,
            self.depth,
            self.parent_fingerprint,
            self.child_number,
            &self.chain_code,
            &key,
        ));
        f.write_str(&s)
    }
}

impl FromStr for Xpriv {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let raw = decode(s)?;
        if raw.version != XPRV_VERSION {
            return Err("not an xprv".to_string());
        }
        if raw.key[0] != 0 {
            return Err("not a private key".to_string());
        }
        let mut bytes = Zeroizing::new([0u8; 32]);
        bytes.copy_from_slice(&raw.key[1..]);
        let key = SecretKey::from_secret_bytes(*bytes).map_err(|_| "not a valid private key".to_string())?;
        Ok(Xpriv {
            depth: raw.depth,
            parent_fingerprint: raw.parent_fingerprint,
            child_number: raw.child_number,
            chain_code: Zeroizing::new(raw.chain_code),
            key,
        })
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Xpub {
    pub depth: u8,
    pub parent_fingerprint: [u8; 4],
    pub child_number: u32,
    chain_code: [u8; 32],
    key: PublicKey,
}

impl Xpub {
    pub fn derive(&self, indices: &[u32]) -> Result<Xpub, String> {
        let mut key = self.clone();
        for &index in indices {
            key = key.child(index)?;
        }
        Ok(key)
    }

    pub fn child(&self, index: u32) -> Result<Xpub, String> {
        if index & HARDENED != 0 {
            return Err("a public key derives no hardened child".to_string());
        }
        if self.depth == u8::MAX {
            return Err("the tree is 255 levels deep".to_string());
        }
        let mut data = Vec::with_capacity(37);
        data.extend_from_slice(&self.key.serialize());
        data.extend_from_slice(&index.to_be_bytes());
        let i = hmac_sha512(&self.chain_code, &data);
        let tweak = Scalar::from_be_bytes(left(&i))
            .map_err(|_| format!("index {index} derives no valid key; use the next"))?;
        let key = self
            .key
            .add_exp_tweak(&tweak)
            .map_err(|_| format!("index {index} derives no valid key; use the next"))?;
        Ok(Xpub {
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: index,
            chain_code: right(&i),
            key,
        })
    }

    pub fn public_key(&self) -> &PublicKey {
        &self.key
    }

    pub fn chain_code(&self) -> &[u8; 32] {
        &self.chain_code
    }

    pub fn fingerprint(&self) -> [u8; 4] {
        fingerprint(&self.key)
    }
}

impl fmt::Display for Xpub {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&encode(
            XPUB_VERSION,
            self.depth,
            self.parent_fingerprint,
            self.child_number,
            &self.chain_code,
            &self.key.serialize(),
        ))
    }
}

impl FromStr for Xpub {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let raw = decode(s)?;
        if raw.version != XPUB_VERSION {
            return Err("not an xpub".to_string());
        }
        let key = PublicKey::from_slice(&raw.key[..]).map_err(|_| "not a valid public key".to_string())?;
        Ok(Xpub {
            depth: raw.depth,
            parent_fingerprint: raw.parent_fingerprint,
            child_number: raw.child_number,
            chain_code: raw.chain_code,
            key,
        })
    }
}

fn fingerprint(key: &PublicKey) -> [u8; 4] {
    let mut fp = [0u8; 4];
    fp.copy_from_slice(&hash160(&key.serialize())[..4]);
    fp
}

fn hmac_sha512(key: &[u8], data: &[u8]) -> Zeroizing<[u8; 64]> {
    let mut mac = Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts a key of any length");
    mac.update(data);
    Zeroizing::new(mac.finalize().into_bytes().into())
}

fn left(i: &[u8; 64]) -> [u8; 32] {
    let mut l = [0u8; 32];
    l.copy_from_slice(&i[..32]);
    l
}

fn right(i: &[u8; 64]) -> [u8; 32] {
    let mut r = [0u8; 32];
    r.copy_from_slice(&i[32..]);
    r
}


fn encode(
    version: [u8; 4],
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: u32,
    chain_code: &[u8; 32],
    key: &[u8; 33],
) -> String {
    let mut bytes = Zeroizing::new(Vec::with_capacity(78));
    bytes.extend_from_slice(&version);
    bytes.push(depth);
    bytes.extend_from_slice(&parent_fingerprint);
    bytes.extend_from_slice(&child_number.to_be_bytes());
    bytes.extend_from_slice(chain_code);
    bytes.extend_from_slice(key);
    bs58::encode(&*bytes).with_check().into_string()
}

struct Raw {
    version: [u8; 4],
    depth: u8,
    parent_fingerprint: [u8; 4],
    child_number: u32,
    chain_code: [u8; 32],
    key: Zeroizing<[u8; 33]>,
}

fn decode(s: &str) -> Result<Raw, String> {
    let bytes = Zeroizing::new(
        bs58::decode(s)
            .with_check(None)
            .into_vec()
            .map_err(|_| "not an extended key".to_string())?,
    );
    if bytes.len() != 78 {
        return Err("not an extended key".to_string());
    }
    let mut raw = Raw {
        version: [0; 4],
        depth: bytes[4],
        parent_fingerprint: [0; 4],
        child_number: u32::from_be_bytes([bytes[9], bytes[10], bytes[11], bytes[12]]),
        chain_code: [0; 32],
        key: Zeroizing::new([0; 33]),
    };
    raw.version.copy_from_slice(&bytes[..4]);
    raw.parent_fingerprint.copy_from_slice(&bytes[5..9]);
    raw.chain_code.copy_from_slice(&bytes[13..45]);
    raw.key.copy_from_slice(&bytes[45..78]);
    if raw.depth == 0 && (raw.parent_fingerprint != [0; 4] || raw.child_number != 0) {
        return Err("a master key has no parent".to_string());
    }
    Ok(raw)
}

#[cfg(test)]
mod tests {
    use super::*;

    const VECTORS: &[(&str, &[(&str, &str, &str)])] = &[
        (
            "000102030405060708090a0b0c0d0e0f",
            &[
                ("m",
                 "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi",
                 "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"),
                ("m/0'",
                 "xprv9uHRZZhk6KAJC1avXpDAp4MDc3sQKNxDiPvvkX8Br5ngLNv1TxvUxt4cV1rGL5hj6KCesnDYUhd7oWgT11eZG7XnxHrnYeSvkzY7d2bhkJ7",
                 "xpub68Gmy5EdvgibQVfPdqkBBCHxA5htiqg55crXYuXoQRKfDBFA1WEjWgP6LHhwBZeNK1VTsfTFUHCdrfp1bgwQ9xv5ski8PX9rL2dZXvgGDnw"),
                ("m/0'/1",
                 "xprv9wTYmMFdV23N2TdNG573QoEsfRrWKQgWeibmLntzniatZvR9BmLnvSxqu53Kw1UmYPxLgboyZQaXwTCg8MSY3H2EU4pWcQDnRnrVA1xe8fs",
                 "xpub6ASuArnXKPbfEwhqN6e3mwBcDTgzisQN1wXN9BJcM47sSikHjJf3UFHKkNAWbWMiGj7Wf5uMash7SyYq527Hqck2AxYysAA7xmALppuCkwQ"),
                ("m/0'/1/2'",
                 "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM",
                 "xpub6D4BDPcP2GT577Vvch3R8wDkScZWzQzMMUm3PWbmWvVJrZwQY4VUNgqFJPMM3No2dFDFGTsxxpG5uJh7n7epu4trkrX7x7DogT5Uv6fcLW5"),
                ("m/0'/1/2'/2",
                 "xprvA2JDeKCSNNZky6uBCviVfJSKyQ1mDYahRjijr5idH2WwLsEd4Hsb2Tyh8RfQMuPh7f7RtyzTtdrbdqqsunu5Mm3wDvUAKRHSC34sJ7in334",
                 "xpub6FHa3pjLCk84BayeJxFW2SP4XRrFd1JYnxeLeU8EqN3vDfZmbqBqaGJAyiLjTAwm6ZLRQUMv1ZACTj37sR62cfN7fe5JnJ7dh8zL4fiyLHV"),
                ("m/0'/1/2'/2/1000000000",
                 "xprvA41z7zogVVwxVSgdKUHDy1SKmdb533PjDz7J6N6mV6uS3ze1ai8FHa8kmHScGpWmj4WggLyQjgPie1rFSruoUihUZREPSL39UNdE3BBDu76",
                 "xpub6H1LXWLaKsWFhvm6RVpEL9P4KfRZSW7abD2ttkWP3SSQvnyA8FSVqNTEcYFgJS2UaFcxupHiYkro49S8yGasTvXEYBVPamhGW6cFJodrTHy"),
            ],
        ),
        (
            "fffcf9f6f3f0edeae7e4e1dedbd8d5d2cfccc9c6c3c0bdbab7b4b1aeaba8a5a29f9c999693908d8a8784817e7b7875726f6c696663605d5a5754514e4b484542",
            &[
                ("m",
                 "xprv9s21ZrQH143K31xYSDQpPDxsXRTUcvj2iNHm5NUtrGiGG5e2DtALGdso3pGz6ssrdK4PFmM8NSpSBHNqPqm55Qn3LqFtT2emdEXVYsCzC2U",
                 "xpub661MyMwAqRbcFW31YEwpkMuc5THy2PSt5bDMsktWQcFF8syAmRUapSCGu8ED9W6oDMSgv6Zz8idoc4a6mr8BDzTJY47LJhkJ8UB7WEGuduB"),
                ("m/0",
                 "xprv9vHkqa6EV4sPZHYqZznhT2NPtPCjKuDKGY38FBWLvgaDx45zo9WQRUT3dKYnjwih2yJD9mkrocEZXo1ex8G81dwSM1fwqWpWkeS3v86pgKt",
                 "xpub69H7F5d8KSRgmmdJg2KhpAK8SR3DjMwAdkxj3ZuxV27CprR9LgpeyGmXUbC6wb7ERfvrnKZjXoUmmDznezpbZb7ap6r1D3tgFxHmwMkQTPH"),
                ("m/0/2147483647'",
                 "xprv9wSp6B7kry3Vj9m1zSnLvN3xH8RdsPP1Mh7fAaR7aRLcQMKTR2vidYEeEg2mUCTAwCd6vnxVrcjfy2kRgVsFawNzmjuHc2YmYRmagcEPdU9",
                 "xpub6ASAVgeehLbnwdqV6UKMHVzgqAG8Gr6riv3Fxxpj8ksbH9ebxaEyBLZ85ySDhKiLDBrQSARLq1uNRts8RuJiHjaDMBU4Zn9h8LZNnBC5y4a"),
                ("m/0/2147483647'/1",
                 "xprv9zFnWC6h2cLgpmSA46vutJzBcfJ8yaJGg8cX1e5StJh45BBciYTRXSd25UEPVuesF9yog62tGAQtHjXajPPdbRCHuWS6T8XA2ECKADdw4Ef",
                 "xpub6DF8uhdarytz3FWdA8TvFSvvAh8dP3283MY7p2V4SeE2wyWmG5mg5EwVvmdMVCQcoNJxGoWaU9DCWh89LojfZ537wTfunKau47EL2dhHKon"),
                ("m/0/2147483647'/1/2147483646'",
                 "xprvA1RpRA33e1JQ7ifknakTFpgNXPmW2YvmhqLQYMmrj4xJXXWYpDPS3xz7iAxn8L39njGVyuoseXzU6rcxFLJ8HFsTjSyQbLYnMpCqE2VbFWc",
                 "xpub6ERApfZwUNrhLCkDtcHTcxd75RbzS1ed54G1LkBUHQVHQKqhMkhgbmJbZRkrgZw4koxb5JaHWkY4ALHY2grBGRjaDMzQLcgJvLJuZZvRcEL"),
                ("m/0/2147483647'/1/2147483646'/2",
                 "xprvA2nrNbFZABcdryreWet9Ea4LvTJcGsqrMzxHx98MMrotbir7yrKCEXw7nadnHM8Dq38EGfSh6dqA9QWTyefMLEcBYJUuekgW4BYPJcr9E7j",
                 "xpub6FnCn6nSzZAw5Tw7cgR9bi15UV96gLZhjDstkXXxvCLsUXBGXPdSnLFbdpq8p9HmGsApME5hQTZ3emM2rnY5agb9rXpVGyy3bdW6EEgAtqt"),
            ],
        ),
        (
            "4b381541583be4423346c643850da4b320e46a87ae3d2a4e6da11eba819cd4acba45d239319ac14f863b8d5ab5a0d0c64d2e8a1e7d1457df2e5a3c51c73235be",
            &[
                ("m",
                 "xprv9s21ZrQH143K25QhxbucbDDuQ4naNntJRi4KUfWT7xo4EKsHt2QJDu7KXp1A3u7Bi1j8ph3EGsZ9Xvz9dGuVrtHHs7pXeTzjuxBrCmmhgC6",
                 "xpub661MyMwAqRbcEZVB4dScxMAdx6d4nFc9nvyvH3v4gJL378CSRZiYmhRoP7mBy6gSPSCYk6SzXPTf3ND1cZAceL7SfJ1Z3GC8vBgp2epUt13"),
                ("m/0'",
                 "xprv9uPDJpEQgRQfDcW7BkF7eTya6RPxXeJCqCJGHuCJ4GiRVLzkTXBAJMu2qaMWPrS7AANYqdq6vcBcBUdJCVVFceUvJFjaPdGZ2y9WACViL4L",
                 "xpub68NZiKmJWnxxS6aaHmn81bvJeTESw724CRDs6HbuccFQN9Ku14VQrADWgqbhhTHBaohPX4CjNLf9fq9MYo6oDaPPLPxSb7gwQN3ih19Zm4Y"),
            ],
        ),
        (
            "3ddd5602285899a946114506157c7997e5444528f3003f6134712147db19b678",
            &[
                ("m",
                 "xprv9s21ZrQH143K48vGoLGRPxgo2JNkJ3J3fqkirQC2zVdk5Dgd5w14S7fRDyHH4dWNHUgkvsvNDCkvAwcSHNAQwhwgNMgZhLtQC63zxwhQmRv",
                 "xpub661MyMwAqRbcGczjuMoRm6dXaLDEhW1u34gKenbeYqAix21mdUKJyuyu5F1rzYGVxyL6tmgBUAEPrEz92mBXjByMRiJdba9wpnN37RLLAXa"),
                ("m/0'",
                 "xprv9vB7xEWwNp9kh1wQRfCCQMnZUEG21LpbR9NPCNN1dwhiZkjjeGRnaALmPXCX7SgjFTiCTT6bXes17boXtjq3xLpcDjzEuGLQBM5ohqkao9G",
                 "xpub69AUMk3qDBi3uW1sXgjCmVjJ2G6WQoYSnNHyzkmdCHEhSZ4tBok37xfFEqHd2AddP56Tqp4o56AePAgCjYdvpW2PU2jbUPFKsav5ut6Ch1m"),
                ("m/0'/1'",
                 "xprv9xJocDuwtYCMNAo3Zw76WENQeAS6WGXQ55RCy7tDJ8oALr4FWkuVoHJeHVAcAqiZLE7Je3vZJHxspZdFHfnBEjHqU5hG1Jaj32dVoS6XLT1",
                 "xpub6BJA1jSqiukeaesWfxe6sNK9CCGaujFFSJLomWHprUL9DePQ4JDkM5d88n49sMGJxrhpjazuXYWdMf17C9T5XnxkopaeS7jGk1GyyVziaMt"),
            ],
        ),
    ];

    const INVALID: &[&str] = &[
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6LBpB85b3D2yc8sfvZU521AAwdZafEz7mnzBBsz4wKY5fTtTQBm",
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGTQQD3dC4H2D5GBj7vWvSQaaBv5cxi9gafk7NF3pnBju6dwKvH",
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Txnt3siSujt9RCVYsx4qHZGc62TG4McvMGcAUjeuwZdduYEvFn",
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFGpWnsj83BHtEy5Zt8CcDr1UiRXuWCmTQLxEK9vbz5gPstX92JQ",
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6N8ZMMXctdiCjxTNq964yKkwrkBJJwpzZS4HS2fxvyYUA4q2Xe4",
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD9y5gkZ6Eq3Rjuahrv17fEQ3Qen6J",
        "xprv9s2SPatNQ9Vc6GTbVMFPFo7jsaZySyzk7L8n2uqKXJen3KUmvQNTuLh3fhZMBoG3G4ZW1N2kZuHEPY53qmbZzCHshoQnNf4GvELZfqTUrcv",
        "xpub661no6RGEX3uJkY4bNnPcw4URcQTrSibUZ4NqJEw5eBkv7ovTwgiT91XX27VbEXGENhYRCf7hyEbWrR3FewATdCEebj6znwMfQkhRYHRLpJ",
        "xprv9s21ZrQH4r4TsiLvyLXqM9P7k1K3EYhA1kkD6xuquB5i39AU8KF42acDyL3qsDbU9NmZn6MsGSUYZEsuoePmjzsB3eFKSUEh3Gu1N3cqVUN",
        "xpub661MyMwAuDcm6CRQ5N4qiHKrJ39Xe1R1NyfouMKTTWcguwVcfrZJaNvhpebzGerh7gucBvzEQWRugZDuDXjNDRmXzSZe4c7mnTK97pTvGS8",
        "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHGMQzT7ayAmfo4z3gY5KfbrZWZ6St24UVf2Qgo6oujFktLHdHY4",
        "DMwo58pR1QLEFihHiXPVykYB6fJmsTeHvyTp7hRThAtCX8CvYzgPcn8XnmdfHPmHJiEDXkTiJTVV9rHEBUem2mwVbbNfvT2MTcAqj3nesx8uBf9",
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzF93Y5wvzdUayhgkkFoicQZcP3y52uPPxFnfoLZB21Teqt1VvEHx",
        "xprv9s21ZrQH143K24Mfq5zL5MhWK9hUhhGbd45hLXo2Pq2oqzMMo63oStZzFAzHGBP2UuGCqWLTAPLcMtD5SDKr24z3aiUvKr9bJpdrcLg1y3G",
        "xpub661MyMwAqRbcEYS8w7XLSVeEsBXy79zSzH1J8vCdxAZningWLdN3zgtU6Q5JXayek4PRsn35jii4veMimro1xefsM58PgBMrvdYre8QyULY",
        "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHL",
    ];

    #[test]
    fn the_bip32_vectors_derive_and_serialise() {
        for (seed, keys) in VECTORS {
            let master = Xpriv::new_master(&hex::decode(seed).unwrap()).unwrap();
            for (path, xprv, xpub) in *keys {
                let key = master.derive(&path.parse().unwrap()).unwrap();
                assert_eq!(key.to_string(), *xprv, "{path}");
                assert_eq!(key.to_xpub().to_string(), *xpub, "{path}");
                let parsed: Xpriv = xprv.parse().unwrap();
                assert_eq!(parsed.to_string(), *xprv);
                assert_eq!(parsed.to_xpub(), key.to_xpub());
                assert_eq!(xpub.parse::<Xpub>().unwrap(), key.to_xpub());
            }
        }
    }

 
    #[test]
    fn public_derivation_matches_private() {
        let master = Xpriv::new_master(&hex::decode(VECTORS[0].0).unwrap()).unwrap();
        let m0h = master.child(HARDENED).unwrap();
        let from_pub = m0h.to_xpub().child(1).unwrap();
        assert_eq!(from_pub, m0h.child(1).unwrap().to_xpub());
        assert_eq!(from_pub.to_string(), VECTORS[0].1[2].2);
        let m0h12h = master.derive(&"m/0'/1/2'".parse().unwrap()).unwrap();
        let deep = m0h12h.to_xpub().derive(&[2, 1_000_000_000]).unwrap();
        assert_eq!(deep.to_string(), VECTORS[0].1[5].2);
        assert!(m0h.to_xpub().child(HARDENED).is_err());
    }

    #[test]
    fn the_bip32_invalid_keys_are_refused() {
        for s in INVALID {
            assert!(s.parse::<Xpriv>().is_err(), "{s}");
            assert!(s.parse::<Xpub>().is_err(), "{s}");
        }
    }

    #[test]
    fn paths_parse_and_print() {
        for (s, indices) in [
            ("m", vec![]),
            ("m/0", vec![0]),
            ("m/0'", vec![HARDENED]),
            ("m/0h", vec![HARDENED]),
            ("m/84'/0'/0'/0/0", vec![84 | HARDENED, HARDENED, HARDENED, 0, 0]),
            ("m/44'/144'/0'/0/0", vec![44 | HARDENED, 144 | HARDENED, HARDENED, 0, 0]),
            ("m/2147483647'", vec![0x7fff_ffff | HARDENED]),
        ] {
            let path: DerivationPath = s.parse().unwrap();
            assert_eq!(path.indices(), &indices[..], "{s}");
            assert_eq!(path.to_string(), s.replace('h', "'"));
        }
        for bad in ["", "84'/0'", "m/", "m//0", "m/x", "m/2147483648", "m/-1", "m/0''", "M/0"] {
            assert!(bad.parse::<DerivationPath>().is_err(), "{bad}");
        }
        let account: DerivationPath = "m/84'/0'/0'".parse().unwrap();
        assert_eq!(account.child(0).unwrap().child(5).unwrap().to_string(), "m/84'/0'/0'/0/5");
        assert!(account.child(HARDENED).is_err());
    }

    #[test]
    fn a_seed_outside_the_range_is_refused() {
        assert!(Xpriv::new_master(&[0u8; 15]).is_err());
        assert!(Xpriv::new_master(&[0u8; 65]).is_err());
        assert!(Xpriv::new_master(&[0u8; 16]).is_ok());
    }

  
    #[test]
    fn the_wallets_account_keys_are_unchanged() {
        let seed = hex::decode("5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4").unwrap();
        let master = Xpriv::new_master(&seed).unwrap();
        for (path, xpub) in [
            ("m/84'/0'/0'", "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V"),
            ("m/86'/0'/0'", "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ"),
            ("m/49'/0'/0'", "xpub6C6nQwHaWbSrzs5tZ1q7m5R9cPK9eYpNMFesiXsYrgc1P8bvLLAet9JfHjYXKjToD8cBRswJXXbbFpXgwsswVPAZzKMa1jUp2kVkGVUaJa7"),
            ("m/44'/0'/0'", "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj"),
        ] {
            assert_eq!(master.derive(&path.parse().unwrap()).unwrap().to_xpub().to_string(), xpub, "{path}");
        }
        let xrp = master.derive(&"m/44'/144'/0'/0/0".parse().unwrap()).unwrap();
        assert_eq!(hex::encode(xrp.secret_key().to_secret_bytes()), "90802a50aa84efb6cdb225f17c27616ea94048c179142fecf03f4712a07ea7a4");
        assert_eq!(hex::encode(xrp.public_key().serialize()), "031d68bc1a142e6766b2bdfb006ccfe135ef2e0e2e94abb5cf5c9ab6104776fbae");
    }

    #[test]
    fn debug_shows_no_key() {
        let master = Xpriv::new_master(&[1u8; 32]).unwrap();
        assert_eq!(format!("{master:?}"), "Xpriv(depth 0, child 0)");
    }
}
