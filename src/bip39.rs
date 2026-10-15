
use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use sha2::{Digest, Sha256, Sha512};
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

mod words;
pub use words::WORDS;

const ROUNDS: u32 = 2048;

#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct Mnemonic {
    indices: Vec<u16>,
}

impl fmt::Debug for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Mnemonic({} words)", self.indices.len())
    }
}

impl Mnemonic {
    pub fn parse(text: &str) -> Result<Mnemonic, String> {
        let mut indices: Zeroizing<Vec<u16>> = Zeroizing::new(Vec::with_capacity(24));
        for word in text.split_whitespace() {
            if indices.len() == 24 {
                return Err("more than 24 words".to_string());
            }
            let index = WORDS
                .binary_search(&word)
                .map_err(|_| format!("word {} is not on the list", indices.len() + 1))?;
            indices.push(index as u16);
        }
        let count = indices.len();
        if !matches!(count, 12 | 15 | 18 | 21 | 24) {
            return Err(format!("{count} words; a phrase has 12, 15, 18, 21 or 24"));
        }
        let mnemonic = Mnemonic { indices: std::mem::take(&mut *indices) };
        let (entropy, checksum) = mnemonic.unpack();
        if checksum != expected_checksum(&entropy, count / 3) {
            return Err("the checksum does not match".to_string());
        }
        Ok(mnemonic)
    }


    pub fn from_entropy(entropy: &[u8]) -> Result<Mnemonic, String> {
        if !matches!(entropy.len(), 16 | 20 | 24 | 28 | 32) {
            return Err(format!(
                "{} bytes of entropy; a phrase takes 16, 20, 24, 28 or 32",
                entropy.len()
            ));
        }
        let entropy_bits = entropy.len() * 8;
        let checksum_bits = entropy.len() / 4;
        let checksum = expected_checksum(entropy, checksum_bits);
        let bit = |n: usize| -> u16 {
            if n < entropy_bits {
                ((entropy[n / 8] >> (7 - n % 8)) & 1) as u16
            } else {
                ((checksum >> (checksum_bits - 1 - (n - entropy_bits))) & 1) as u16
            }
        };
        let count = (entropy_bits + checksum_bits) / 11;
        let mut indices = Vec::with_capacity(count);
        for word in 0..count {
            let mut index = 0u16;
            for b in 0..11 {
                index = (index << 1) | bit(word * 11 + b);
            }
            indices.push(index);
        }
        Ok(Mnemonic { indices })
    }

    pub fn to_entropy(&self) -> Zeroizing<Vec<u8>> {
        self.unpack().0
    }

    pub fn word_count(&self) -> usize {
        self.indices.len()
    }

    pub fn words(&self) -> impl Iterator<Item = &'static str> + '_ {
        self.indices.iter().map(|&i| WORDS[i as usize])
    }

    pub fn to_seed(&self, passphrase: &str) -> [u8; 64] {
        let mut sentence: Zeroizing<String> = Zeroizing::new(String::with_capacity(24 * 9));
        for (i, word) in self.words().enumerate() {
            if i > 0 {
                sentence.push(' ');
            }
            sentence.push_str(word);
        }
        let password: Zeroizing<String> = Zeroizing::new(sentence.as_str().nfkd().collect());
        let normalised: Zeroizing<String> = Zeroizing::new(passphrase.nfkd().collect());
        let mut salt: Zeroizing<Vec<u8>> = Zeroizing::new(b"mnemonic".to_vec());
        salt.extend_from_slice(normalised.as_bytes());
        pbkdf2_sha512(password.as_bytes(), &salt)
    }

    fn bits(&self) -> impl Iterator<Item = bool> + '_ {
        self.indices
            .iter()
            .flat_map(|&index| (0..11).rev().map(move |b| (index >> b) & 1 == 1))
    }

  
    fn unpack(&self) -> (Zeroizing<Vec<u8>>, u32) {
        let count = self.indices.len();
        let entropy_bits = count * 32 / 3;
        let mut entropy = Zeroizing::new(vec![0u8; entropy_bits / 8]);
        let mut checksum = 0u32;
        for (n, bit) in self.bits().enumerate() {
            if !bit {
                continue;
            }
            if n < entropy_bits {
                entropy[n / 8] |= 0x80 >> (n % 8);
            } else {
                checksum |= 1 << (count * 11 - 1 - n);
            }
        }
        (entropy, checksum)
    }
}

impl fmt::Display for Mnemonic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, word) in self.words().enumerate() {
            if i > 0 {
                f.write_str(" ")?;
            }
            f.write_str(word)?;
        }
        Ok(())
    }
}

fn expected_checksum(entropy: &[u8], bits: usize) -> u32 {
    (Sha256::digest(entropy)[0] >> (8 - bits)) as u32
}


fn pbkdf2_sha512(password: &[u8], salt: &[u8]) -> [u8; 64] {
    let prf = Hmac::<Sha512>::new_from_slice(password).expect("HMAC accepts a key of any length");
    let mut mac = prf.clone();
    mac.update(salt);
    mac.update(&1u32.to_be_bytes());
    let mut u: Zeroizing<[u8; 64]> = Zeroizing::new(mac.finalize().into_bytes().into());
    let mut out = *u;
    for _ in 1..ROUNDS {
        let mut mac = prf.clone();
        mac.update(&*u);
        *u = mac.finalize().into_bytes().into();
        for (o, b) in out.iter_mut().zip(u.iter()) {
            *o ^= b;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const ABANDON: &str =
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

    const VECTORS: &[(&str, &str, &str)] = &[
        (
            "00000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank yellow",
            "2e8905819b8723fe2c1d161860e5ee1830318dbf49a83bd451cfb8440c28bd6fa457fe1296106559a3c80937a1c1069be3a3a5bd381ee6260e8d9739fce1f607",
        ),
        (
            "80808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage above",
            "d71de856f81a8acc65e6fc851a38d4d7ec216fd0796d0a6827a3ad6ed5511a30fa280f12eb2e47ed2ac03b5c462a0358d18d69fe4f985ec81778c1b370b652a8",
        ),
        (
            "ffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo wrong",
            "ac27495480225222079d7be181583751e86f571027b0497b5b5d11218e0a8a13332572917f0f8e5a589620c6f15b11c61dee327651a14c34e18231052e48c069",
        ),
        (
            "000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon agent",
            "035895f2f481b1b0f01fcf8c289c794660b289981a78f8106447707fdd9666ca06da5a9a565181599b79f53b844d8a71dd9f439c52a3d7b3e8a79c906ac845fa",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal will",
            "f2b94508732bcbacbcc020faefecfc89feafa6649a5491b8c952cede496c214a0c7b3c392d168748f2d4a612bada0753b52a1c7ac53c1e93abd5c6320b9e95dd",
        ),
        (
            "808080808080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter always",
            "107d7c02a5aa6f38c58083ff74f04c607c2d2c0ecc55501dadd72d025b751bc27fe913ffb796f841c49b1d33b610cf0e91d3aa239027f5e99fe4ce9e5088cd65",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo when",
            "0cd6e5d827bb62eb8fc1e262254223817fd068a74b5b449cc2f667c3f1f985a76379b43348d952e2265b4cd129090758b3e3c2c49103b5051aac2eaeb890a528",
        ),
        (
            "0000000000000000000000000000000000000000000000000000000000000000",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon art",
            "bda85446c68413707090a52022edd26a1c9462295029f2e60cd7c4f2bbd3097170af7a4d73245cafa9c3cca8d561a7c3de6f5d4a10be8ed2a5e608d68f92fcc8",
        ),
        (
            "7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f7f",
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
            "bc09fca1804f7e69da93c2f2028eb238c227f2e9dda30cd63699232578480a4021b146ad717fbb7e451ce9eb835f43620bf5c514db0f8add49f5d121449d3e87",
        ),
        (
            "8080808080808080808080808080808080808080808080808080808080808080",
            "letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic avoid letter advice cage absurd amount doctor acoustic bless",
            "c0c519bd0e91a2ed54357d9d1ebef6f5af218a153624cf4f2da911a0ed8f7a09e2ef61af0aca007096df430022f7a2b6fb91661a9589097069720d015e4e982f",
        ),
        (
            "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
            "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote",
            "dd48c104698c30cfe2b6142103248622fb7bb0ff692eebb00089b32d22484e1613912f0a5b694407be899ffd31ed3992c456cdf60f5d4564b8ba3f05a69890ad",
        ),
        (
            "9e885d952ad362caeb4efe34a8e91bd2",
            "ozone drill grab fiber curtain grace pudding thank cruise elder eight picnic",
            "274ddc525802f7c828d8ef7ddbcdc5304e87ac3535913611fbbfa986d0c9e5476c91689f9c8a54fd55bd38606aa6a8595ad213d4c9c9f9aca3fb217069a41028",
        ),
        (
            "6610b25967cdcca9d59875f5cb50b0ea75433311869e930b",
            "gravity machine north sort system female filter attitude volume fold club stay feature office ecology stable narrow fog",
            "628c3827a8823298ee685db84f55caa34b5cc195a778e52d45f59bcf75aba68e4d7590e101dc414bc1bbd5737666fbbef35d1f1903953b66624f910feef245ac",
        ),
        (
            "68a79eaca2324873eacc50cb9c6eca8cc68ea5d936f98787c60c7ebc74e6ce7c",
            "hamster diagram private dutch cause delay private meat slide toddler razor book happy fancy gospel tennis maple dilemma loan word shrug inflict delay length",
            "64c87cde7e12ecf6704ab95bb1408bef047c22db4cc7491c4271d170a1b213d20b385bc1588d9c7b38f1b39d415665b8a9030c9ec653d75e65f847d8fc1fc440",
        ),
        (
            "c0ba5a8e914111210f2bd131f3d5e08d",
            "scheme spot photo card baby mountain device kick cradle pact join borrow",
            "ea725895aaae8d4c1cf682c1bfd2d358d52ed9f0f0591131b559e2724bb234fca05aa9c02c57407e04ee9dc3b454aa63fbff483a8b11de949624b9f1831a9612",
        ),
        (
            "6d9be1ee6ebd27a258115aad99b7317b9c8d28b6d76431c3",
            "horn tenant knee talent sponsor spell gate clip pulse soap slush warm silver nephew swap uncle crack brave",
            "fd579828af3da1d32544ce4db5c73d53fc8acc4ddb1e3b251a31179cdb71e853c56d2fcb11aed39898ce6c34b10b5382772db8796e52837b54468aeb312cfc3d",
        ),
        (
            "9f6a2878b2520799a44ef18bc7df394e7061a224d2c33cd015b157d746869863",
            "panda eyebrow bullet gorilla call smoke muffin taste mesh discover soft ostrich alcohol speed nation flash devote level hobby quick inner drive ghost inside",
            "72be8e052fc4919d2adf28d5306b5474b0069df35b02303de8c1729c9538dbb6fc2d731d5f832193cd9fb6aeecbc469594a70e3dd50811b5067f3b88b28c3e8d",
        ),
        (
            "23db8160a31d3e0dca3688ed941adbf3",
            "cat swing flag economy stadium alone churn speed unique patch report train",
            "deb5f45449e615feff5640f2e49f933ff51895de3b4381832b3139941c57b59205a42480c52175b6efcffaa58a2503887c1e8b363a707256bdd2b587b46541f5",
        ),
        (
            "8197a4a47f0425faeaa69deebc05ca29c0a5b5cc76ceacc0",
            "light rule cinnamon wrap drastic word pride squirrel upgrade then income fatal apart sustain crack supply proud access",
            "4cbdff1ca2db800fd61cae72a57475fdc6bab03e441fd63f96dabd1f183ef5b782925f00105f318309a7e9c3ea6967c7801e46c8a58082674c860a37b93eda02",
        ),
        (
            "066dca1a2bb7e8a1db2832148ce9933eea0f3ac9548d793112d9a95c9407efad",
            "all hour make first leader extend hole alien behind guard gospel lava path output census museum junior mass reopen famous sing advance salt reform",
            "26e975ec644423f4a4c4f4215ef09b4bd7ef924e85d1d17c4cf3f136c2863cf6df0a475045652c57eb5fb41513ca2a2d67722b77e954b4b3fc11f7590449191d",
        ),
        (
            "f30f8c1da665478f49b001d94c5fc452",
            "vessel ladder alter error federal sibling chat ability sun glass valve picture",
            "2aaa9242daafcee6aa9d7269f17d4efe271e1b9a529178d7dc139cd18747090bf9d60295d0ce74309a78852a9caadf0af48aae1c6253839624076224374bc63f",
        ),
        (
            "c10ec20dc3cd9f652c7fac2f1230f7a3c828389a14392f05",
            "scissors invite lock maple supreme raw rapid void congress muscle digital elegant little brisk hair mango congress clump",
            "7b4a10be9d98e6cba265566db7f136718e1398c71cb581e1b2f464cac1ceedf4f3e274dc270003c670ad8d02c4558b2f8e39edea2775c9e232c7cb798b069e88",
        ),
        (
            "f585c11aec520db57dd353c69554b21a89b20fb0650966fa0a9d6f74fd989d8f",
            "void come effort suffer camp survey warrior heavy shoot primary clutch crush open amazing screen patrol group space point ten exist slush involve unfold",
            "01f5bced59dec48e362f2c45b5de68b9fd6c92c6634f44d6d40aab69056506f0e35524a518034ddc1192e1dacd32c1ed3eaa3c3b131c88ed8e7e54c49a5d0998",
        ),
    ];

    #[test]
    fn the_bip39_vectors_round_trip_and_stretch() {
        for (entropy, phrase, seed) in VECTORS {
            let entropy = hex::decode(entropy).unwrap();
            let from_entropy = Mnemonic::from_entropy(&entropy).unwrap();
            assert_eq!(from_entropy.to_string(), *phrase);
            let parsed = Mnemonic::parse(phrase).unwrap();
            assert_eq!(parsed, from_entropy);
            assert_eq!(&*parsed.to_entropy(), &entropy);
            assert_eq!(hex::encode(parsed.to_seed("TREZOR")), *seed, "{phrase}");
        }
    }

    #[test]
    fn parsing_is_lenient_on_whitespace_and_strict_on_words() {
        for ok in [
            ABANDON.to_string(),
            format!("  {ABANDON}  "),
            ABANDON.replace(' ', "  "),
            ABANDON.replace(' ', "\n"),
        ] {
            let m = Mnemonic::parse(&ok).unwrap();
            assert_eq!(m.word_count(), 12);
            assert_eq!(hex::encode(m.to_entropy()), "00000000000000000000000000000000");
        }
        assert!(Mnemonic::parse(&ABANDON.to_uppercase()).unwrap_err().contains("word 1"));
        assert!(Mnemonic::parse(&ABANDON.replace("about", "About")).unwrap_err().contains("word 12"));
        assert!(Mnemonic::parse(&ABANDON.replace("about", "zzz")).unwrap_err().contains("word 12"));
        assert!(Mnemonic::parse(&ABANDON.replace(" about", "")).unwrap_err().contains("11 words"));
        assert!(Mnemonic::parse(&ABANDON.replace("about", "abandon")).unwrap_err().contains("checksum"));
        assert!(Mnemonic::parse("").unwrap_err().contains("0 words"));
        assert!(Mnemonic::parse(&format!("{ABANDON} {ABANDON} {ABANDON}")).unwrap_err().contains("more than 24"));
        let zoo = "zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo zoo vote";
        assert_eq!(hex::encode(Mnemonic::parse(zoo).unwrap().to_entropy()), "ff".repeat(32));
    }

    #[test]
    fn a_24_word_phrase_from_fixed_entropy_matches_the_wallet() {
        let m = Mnemonic::from_entropy(&[0x42u8; 32]).unwrap();
        assert_eq!(
            m.to_string(),
            "drastic bamboo mountain loyal category cancel animal embark drastic bamboo mountain loyal category cancel animal embark drastic bamboo mountain loyal category cancel animal embark"
        );
        assert_eq!(
            hex::encode(m.to_seed("TREZOR")),
            "388639d885c6e32c8f16808d9133fc39ea120078d06d835b69a84d9c0a9f51a5eefce173fa307a0e2e4dca339c1abd58f82cd352dab4d8c1812bc866425be713"
        );
        for bad in [0usize, 4, 17, 36] {
            assert!(Mnemonic::from_entropy(&vec![0u8; bad]).is_err(), "{bad} bytes");
        }
    }

   
    #[test]
    fn the_seed_without_a_passphrase() {
        assert_eq!(
            hex::encode(Mnemonic::parse(ABANDON).unwrap().to_seed("")),
            "5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4"
        );
    }

    #[test]
    fn the_passphrase_is_normalised() {
        let m = Mnemonic::parse(ABANDON).unwrap();
        assert_eq!(m.to_seed("caf\u{e9}"), m.to_seed("cafe\u{301}"));
        assert_ne!(m.to_seed("cafe"), m.to_seed("caf\u{e9}"));
    }

    #[test]
    fn the_word_list_is_the_standard_one() {
        assert_eq!(WORDS.len(), 2048);
        assert_eq!(WORDS[0], "abandon");
        assert_eq!(WORDS[2047], "zoo");
        assert!(WORDS.windows(2).all(|w| w[0] < w[1]), "sorted, so binary search finds every word");
        assert_eq!(WORDS.iter().map(|w| w.len()).max(), Some(8));
        assert!(WORDS.iter().all(|w| w.bytes().all(|b| b.is_ascii_lowercase())));
    }

    #[test]
    fn debug_shows_no_words() {
        let m = Mnemonic::parse(ABANDON).unwrap();
        assert_eq!(format!("{m:?}"), "Mnemonic(12 words)");
    }
}
