# dannesk-btc-codec

[![Rust](https://img.shields.io/badge/Rust-2024_edition-000000?logo=rust&logoColor=white)](https://www.rust-lang.org)
[![ci](https://github.com/Dannesk/dannesk-btc-codec/actions/workflows/ci.yml/badge.svg)](https://github.com/Dannesk/dannesk-btc-codec/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-3B3F43)](LICENSE)

This is the crate the dannesk app uses for recovery phrases, hierarchical keys, the four standard address types, and the signature hashes. It stands on a
few primitives, `secp256k1` for the curve and RustCrypto's `sha2`, `ripemd` and
`hmac` for the hashes, with `bs58` for base58check. 

## Example

```rust
use dannesk_btc_codec::address::Address;
use dannesk_btc_codec::bip32::Xpriv;
use dannesk_btc_codec::bip39::Mnemonic;
use dannesk_btc_codec::tx::{OutPoint, SEQUENCE_RBF, Transaction, TxIn, TxOut};
use dannesk_btc_codec::{hash160, sighash, sign};

// The first native segwit key of a phrase.
let seed = Mnemonic::parse("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")?.to_seed("");
let key = Xpriv::new_master(&seed)?.derive(&"m/84'/0'/0'/0/0".parse()?)?;
let address = Address::p2wpkh(&key.public_key());
assert_eq!(address.to_string(), "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu");

// Spend one of its coins to a recipient.
let coin = OutPoint { txid: "11".repeat(32).parse()?, vout: 0 };
let mut tx = Transaction {
    version: 2,
    lock_time: 0,
    input: vec![TxIn { previous_output: coin, script_sig: vec![], sequence: SEQUENCE_RBF, witness: vec![] }],
    output: vec![TxOut { value: 40_000, script_pubkey: Address::parse("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4")?.script_pubkey() }],
};
let pubkey = key.public_key().serialize();
let digest = sighash::p2wpkh(&tx, 0, &hash160(&pubkey), 50_000)?;
tx.input[0].witness = vec![sign::ecdsa_sighash_all(&digest, key.secret_key()), pubkey.to_vec()];
let to_broadcast = tx.to_hex();
# Ok::<(), String>(())
```

A taproot input is signed with `sighash::taproot_key_spend` and `sign::schnorr_key_spend`, which
takes 32 bytes of fresh randomness from the caller; a legacy one with `sighash::legacy` over the
coin's own script.

## License

MIT. See [LICENSE](LICENSE).





