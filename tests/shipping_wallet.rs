//! The wallet as it signed on 2026-10-10 with the `bitcoin` crate, from the
//! `abandon … about` phrase: every address it derives in each of its four
//! types, its account keys, and a four-input transaction, one input per type,
//! signed byte for byte as it was. ECDSA is deterministic, and the taproot
//! input was signed with zero auxiliary randomness so that it is too.

use dannesk_btc_codec::address::Address;
use dannesk_btc_codec::bip32::{DerivationPath, Xpriv};
use dannesk_btc_codec::bip39::Mnemonic;
use dannesk_btc_codec::secp256k1::PublicKey;
use dannesk_btc_codec::tx::{OutPoint, SEQUENCE_RBF, Transaction, TxIn, TxOut, Txid};
use dannesk_btc_codec::{hash160, script, sighash, sign};

const ABANDON: &str =
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";

/// A family of addresses, as the wallet's `BtcScriptType` names them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Family {
    Native,
    Taproot,
    Nested,
    Legacy,
}

impl Family {
    fn purpose(self) -> u32 {
        match self {
            Family::Native => 84,
            Family::Taproot => 86,
            Family::Nested => 49,
            Family::Legacy => 44,
        }
    }

    fn address(self, key: &PublicKey) -> Address {
        match self {
            Family::Native => Address::p2wpkh(key),
            Family::Taproot => Address::p2tr(&key.x_only_public_key().0),
            Family::Nested => Address::p2sh_p2wpkh(key),
            Family::Legacy => Address::p2pkh(key),
        }
    }
}

/// (family, account xpub, receive #0, change #0, receive #5, #0 secret, #0 key, #0 script)
const FAMILIES: &[(Family, &str, &str, &str, &str, &str, &str, &str)] = &[
    (
        Family::Native,
        "xpub6CatWdiZiodmUeTDp8LT5or8nmbKNcuyvz7WyksVFkKB4RHwCD3XyuvPEbvqAQY3rAPshWcMLoP2fMFMKHPJ4ZeZXYVUhLv1VMrjPC7PW6V",
        "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
        "bc1q8c6fshw2dlwun7ekn9qwf37cu2rn755upcp6el",
        "bc1qnpzzqjzet8gd5gl8l6gzhuc4s9xv0djt0rlu7a",
        "4604b4b710fe91f584fff084e1a9159fe4f8408fff380596a604948474ce4fa3",
        "0330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c",
        "0014c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2",
    ),
    (
        Family::Taproot,
        "xpub6BgBgsespWvERF3LHQu6CnqdvfEvtMcQjYrcRzx53QJjSxarj2afYWcLteoGVky7D3UKDP9QyrLprQ3VCECoY49yfdDEHGCtMMj92pReUsQ",
        "bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
        "bc1p3qkhfews2uk44qtvauqyr2ttdsw7svhkl9nkm9s9c3x4ax5h60wqwruhk7",
        "bc1pl4frjws098l3nslfjlnry6jxt46w694kuexvs5ar0cmkvxyahfkq0m445f",
        "41f41d69260df4cf277826a9b65a3717e4eeddbeedf637f212ca096576479361",
        "03cc8a4bc64d897bddc5fbc2f670f7a8ba0b386779106cf1223c6fc5d7cd6fc115",
        "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c",
    ),
    (
        Family::Nested,
        "xpub6C6nQwHaWbSrzs5tZ1q7m5R9cPK9eYpNMFesiXsYrgc1P8bvLLAet9JfHjYXKjToD8cBRswJXXbbFpXgwsswVPAZzKMa1jUp2kVkGVUaJa7",
        "37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
        "34K56kSjgUCUSD8GTtuF7c9Zzwokbs6uZ7",
        "3QrMAP4ZG3a7Y1qFF5A4sY8MeSUxZ8Yxjy",
        "508c73a06f6b6c817238ba61be232f5080ea4616c54f94771156934666d38ee3",
        "039b3b694b8fc5b5e07fb069c783cac754f5d38c3e08bed1960e31fdb1dda35c24",
        "a9143fb6e95812e57bb4691f9a4a628862a61a4f769b87",
    ),
    (
        Family::Legacy,
        "xpub6BosfCnifzxcFwrSzQiqu2DBVTshkCXacvNsWGYJVVhhawA7d4R5WSWGFNbi8Aw6ZRc1brxMyWMzG3DSSSSoekkudhUd9yLb6qx39T9nMdj",
        "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
        "1J3J6EvPrv8q6AC3VCjWV45Uf3nssNMRtH",
        "19a7HGg32ecPQo49rDeM2NSFJHPqrwSJto",
        "e284129cc0922579a535bbf4d1a3b25773090d28c909bc0fed73b5e0222cc372",
        "03aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5e",
        "76a914d986ed01b7a22225a70edbf2ba7cfb63a15cb3aa88ac",
    ),
];

const UNSIGNED_TX: &str = "020000000411111111111111111111111111111111111111111111111111111111111111110000000000fdffffff12121212121212121212121212121212121212121212121212121212121212120100000000fdffffff13131313131313131313131313131313131313131313131313131313131313130200000000fdffffff14141414141414141414141414141414141414141414141414141414141414140300000000fdffffff02a086010000000000160014751e76e8199196d454941c45d1b3a323f1433bd6a686010000000000160014c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e200000000";
const SIGNED_TX: &str = "0200000000010411111111111111111111111111111111111111111111111111111111111111110000000000fdffffff12121212121212121212121212121212121212121212121212121212121212120100000000fdffffff13131313131313131313131313131313131313131313131313131313131313130200000017160014f990679acafe25c27615373b40bf22446d24ff44fdffffff1414141414141414141414141414141414141414141414141414141414141414030000006a473044022076e3772f3ad10c012e557de5f9484746a1c5678edad4efd1bc121652a1a92d230220691d389995b38a8cde0076db8330ce6637e8ca5b2702095262d75d3a952f06b9012103aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5efdffffff02a086010000000000160014751e76e8199196d454941c45d1b3a323f1433bd6a686010000000000160014c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e20247304402206b66a37ac3655b0f34a15adc2709fc8476fde36c9e1ee8f67063c4b6e588e57e022016c93e2e92fc172178f1e21a17608b778072e1d8cab2714c4cf8b4bc08e9ef2701210330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c014001cd1e375030830678fce7fafd63243a462548d36c06c05b38978c75ab1e53f06e4083976711d082281116a9d733e2326731c8846275520c459dfae2c9acc8bf0247304402201ecd50029a61a940fd3a6e43b74963d37f86f7bef9ca10bb237c7ab117e8e201022079c726041f676ff016688faa00960c01442783c3a0adefca1e9a0c9d7a8770db0121039b3b694b8fc5b5e07fb069c783cac754f5d38c3e08bed1960e31fdb1dda35c240000000000";
const SIGNED_TXID: &str = "dcb9559e17ad9ea1d6e26263ad8086b020730288d2aad53713d92b0add4eead8";

const SIGHASHES: [&str; 4] = [
    "68ce37c189600b4740ac8676e1d1dfba6208c7b5ddf7a35158eb16504176bd4b",
    "dc1eaa3584a92fbb8ca0e7378b996561a4f13d117bbad7479b173228fc0a73e7",
    "bd3321235837d37fceb91b5c8dbeb7246afa25ded52e7407eacf052117a4ea3c",
    "280e533c81ee6651c143d1b5606de0743f1c5a6c98462128b1d05eae6bdac96c",
];

#[test]
fn every_address_the_wallet_derives_is_unchanged() {
    let seed = Mnemonic::parse(ABANDON).unwrap().to_seed("");
    let master = Xpriv::new_master(&seed).unwrap();
    assert_eq!(master.to_string(), "xprv9s21ZrQH143K3GJpoapnV8SFfukcVBSfeCficPSGfubmSFDxo1kuHnLisriDvSnRRuL2Qrg5ggqHKNVpxR86QEC8w35uxmGoggxtQTPvfUu");
    for (family, account_xpub, receive0, change0, receive5, secret, pubkey, spk) in FAMILIES {
        let purpose = family.purpose();
        let account = master.derive(&format!("m/{purpose}'/0'/0'").parse::<DerivationPath>().unwrap()).unwrap();
        let xpub = account.to_xpub();
        assert_eq!(xpub.to_string(), *account_xpub, "{family:?}");
        // The receive screen mints from the stored xpub string.
        let stored = account_xpub.parse::<dannesk_btc_codec::bip32::Xpub>().unwrap();
        let at = |chain: u32, index: u32| family.address(stored.derive(&[chain, index]).unwrap().public_key()).to_string();
        assert_eq!(at(0, 0), *receive0, "{family:?}");
        assert_eq!(at(1, 0), *change0, "{family:?}");
        assert_eq!(at(0, 5), *receive5, "{family:?}");
        // And signing derives the member's secret from the seed.
        let member = master.derive(&format!("m/{purpose}'/0'/0'/0/0").parse::<DerivationPath>().unwrap()).unwrap();
        assert_eq!(hex::encode(member.secret_key().to_secret_bytes()), *secret, "{family:?}");
        assert_eq!(hex::encode(member.public_key().serialize()), *pubkey, "{family:?}");
        assert_eq!(hex::encode(family.address(&member.public_key()).script_pubkey()), *spk, "{family:?}");
        assert_eq!(family.address(&member.public_key()).to_string(), *receive0, "{family:?}");
    }
}

#[test]
fn the_wallet_signs_the_same_bytes_as_before() {
    let seed = Mnemonic::parse(ABANDON).unwrap().to_seed("");
    let master = Xpriv::new_master(&seed).unwrap();
    let owners: Vec<_> = FAMILIES
        .iter()
        .map(|(family, ..)| {
            let path: DerivationPath = format!("m/{}'/0'/0'/0/0", family.purpose()).parse().unwrap();
            (*family, master.derive(&path).unwrap())
        })
        .collect();

    // One coin per family, 50 000 + i sats, paid to a bc1q recipient with
    // change to native #0: version 2, lock time 0, BIP-125 sequences.
    let recipient = Address::parse("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4").unwrap();
    let change = Address::p2wpkh(&owners[0].1.public_key());
    let coins: Vec<(Txid, u32, u64)> = (0..4)
        .map(|i| (format!("{:02x}", 0x11 + i).repeat(32).parse().unwrap(), i as u32, 50_000 + i as u64))
        .collect();
    let mut tx = Transaction {
        version: 2,
        lock_time: 0,
        input: coins
            .iter()
            .map(|(txid, vout, _)| TxIn {
                previous_output: OutPoint { txid: *txid, vout: *vout },
                script_sig: Vec::new(),
                sequence: SEQUENCE_RBF,
                witness: Vec::new(),
            })
            .collect(),
        output: vec![
            TxOut { value: 100_000, script_pubkey: recipient.script_pubkey() },
            TxOut { value: 100_006, script_pubkey: change.script_pubkey() },
        ],
    };
    assert_eq!(tx.to_hex(), UNSIGNED_TX);

    let prevouts: Vec<TxOut> = coins
        .iter()
        .zip(&owners)
        .map(|((_, _, sats), (family, key))| TxOut { value: *sats, script_pubkey: family.address(&key.public_key()).script_pubkey() })
        .collect();
    let mut signed = Vec::new();
    for (i, (family, key)) in owners.iter().enumerate() {
        let pubkey = key.public_key().serialize();
        let (script_sig, witness) = match family {
            Family::Native | Family::Nested => {
                let digest = sighash::p2wpkh(&tx, i, &hash160(&pubkey), coins[i].2).unwrap();
                assert_eq!(hex::encode(digest), SIGHASHES[i], "input {i}");
                let sig = sign::ecdsa_sighash_all(&digest, key.secret_key());
                let script_sig = if *family == Family::Nested { script::p2sh_p2wpkh_script_sig(&pubkey) } else { Vec::new() };
                (script_sig, vec![sig, pubkey.to_vec()])
            }
            Family::Legacy => {
                let digest = sighash::legacy(&tx, i, &prevouts[i].script_pubkey).unwrap();
                assert_eq!(hex::encode(digest), SIGHASHES[i], "input {i}");
                let sig = sign::ecdsa_sighash_all(&digest, key.secret_key());
                (script::p2pkh_script_sig(&sig, &pubkey), Vec::new())
            }
            Family::Taproot => {
                let digest = sighash::taproot_key_spend(&tx, i, &prevouts).unwrap();
                assert_eq!(hex::encode(digest), SIGHASHES[i], "input {i}");
                let sig = sign::schnorr_key_spend(&digest, key.secret_key(), &[0u8; 32]);
                (Vec::new(), vec![sig.to_vec()])
            }
        };
        signed.push((script_sig, witness));
    }
    for (input, (script_sig, witness)) in tx.input.iter_mut().zip(signed) {
        input.script_sig = script_sig;
        input.witness = witness;
    }
    assert_eq!(tx.to_hex(), SIGNED_TX);
    assert_eq!(tx.txid().to_string(), SIGNED_TXID);
    assert_eq!(tx.vsize(), 436);
    assert_eq!(Transaction::from_hex(SIGNED_TX).unwrap(), tx);
}
