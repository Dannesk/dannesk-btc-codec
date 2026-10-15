

use crate::tx::{Transaction, TxOut, write_output, write_var_bytes, write_varint};
use crate::{script, sha256, sha256d, tagged_hash};

pub const SIGHASH_DEFAULT: u8 = 0x00;
pub const SIGHASH_ALL: u8 = 0x01;
pub const SIGHASH_NONE: u8 = 0x02;
pub const SIGHASH_SINGLE: u8 = 0x03;
pub const SIGHASH_ANYONECANPAY: u8 = 0x80;


pub fn legacy(tx: &Transaction, input: usize, script_code: &[u8]) -> Result<[u8; 32], String> {
    if input >= tx.input.len() {
        return Err(format!("input {input} of {}", tx.input.len()));
    }
    let mut out = Vec::new();
    out.extend_from_slice(&tx.version.to_le_bytes());
    write_varint(&mut out, tx.input.len() as u64);
    for (i, txin) in tx.input.iter().enumerate() {
        out.extend_from_slice(&txin.previous_output.txid.to_bytes());
        out.extend_from_slice(&txin.previous_output.vout.to_le_bytes());
        write_var_bytes(&mut out, if i == input { script_code } else { &[] });
        out.extend_from_slice(&txin.sequence.to_le_bytes());
    }
    write_varint(&mut out, tx.output.len() as u64);
    for output in &tx.output {
        write_output(&mut out, output);
    }
    out.extend_from_slice(&tx.lock_time.to_le_bytes());
    out.extend_from_slice(&(SIGHASH_ALL as u32).to_le_bytes());
    Ok(sha256d(&out))
}


pub fn p2wpkh(tx: &Transaction, input: usize, pubkey_hash: &[u8; 20], amount: u64) -> Result<[u8; 32], String> {
    segwit_v0(tx, input, &script::p2pkh(pubkey_hash), amount)
}


pub fn segwit_v0(tx: &Transaction, input: usize, script_code: &[u8], amount: u64) -> Result<[u8; 32], String> {
    let txin = tx.input.get(input).ok_or_else(|| format!("input {input} of {}", tx.input.len()))?;
    let mut prevouts = Vec::with_capacity(tx.input.len() * 36);
    let mut sequences = Vec::with_capacity(tx.input.len() * 4);
    for i in &tx.input {
        prevouts.extend_from_slice(&i.previous_output.txid.to_bytes());
        prevouts.extend_from_slice(&i.previous_output.vout.to_le_bytes());
        sequences.extend_from_slice(&i.sequence.to_le_bytes());
    }
    let mut outputs = Vec::new();
    for o in &tx.output {
        write_output(&mut outputs, o);
    }
    let mut out = Vec::with_capacity(156 + script_code.len());
    out.extend_from_slice(&tx.version.to_le_bytes());
    out.extend_from_slice(&sha256d(&prevouts));
    out.extend_from_slice(&sha256d(&sequences));
    out.extend_from_slice(&txin.previous_output.txid.to_bytes());
    out.extend_from_slice(&txin.previous_output.vout.to_le_bytes());
    write_var_bytes(&mut out, script_code);
    out.extend_from_slice(&amount.to_le_bytes());
    out.extend_from_slice(&txin.sequence.to_le_bytes());
    out.extend_from_slice(&sha256d(&outputs));
    out.extend_from_slice(&tx.lock_time.to_le_bytes());
    out.extend_from_slice(&(SIGHASH_ALL as u32).to_le_bytes());
    Ok(sha256d(&out))
}


pub fn taproot_key_spend(tx: &Transaction, input: usize, prevouts: &[TxOut]) -> Result<[u8; 32], String> {
    taproot(tx, input, prevouts, SIGHASH_DEFAULT)
}

pub fn taproot(tx: &Transaction, input: usize, prevouts: &[TxOut], hash_type: u8) -> Result<[u8; 32], String> {
    if !matches!(hash_type, 0x00 | 0x01 | 0x02 | 0x03 | 0x81 | 0x82 | 0x83) {
        return Err(format!("hash type {hash_type:#04x} is not defined"));
    }
    if prevouts.len() != tx.input.len() {
        return Err(format!("{} prevouts for {} inputs", prevouts.len(), tx.input.len()));
    }
    let txin = tx.input.get(input).ok_or_else(|| format!("input {input} of {}", tx.input.len()))?;
    let anyone_can_pay = hash_type & SIGHASH_ANYONECANPAY != 0;
    let output_type = if hash_type == SIGHASH_DEFAULT { SIGHASH_ALL } else { hash_type & 0x03 };
    if output_type == SIGHASH_SINGLE && input >= tx.output.len() {
        return Err("SIGHASH_SINGLE with no output at the input's index".to_string());
    }

    let mut msg = Vec::with_capacity(206);
    msg.push(hash_type);
    msg.extend_from_slice(&tx.version.to_le_bytes());
    msg.extend_from_slice(&tx.lock_time.to_le_bytes());
    if !anyone_can_pay {
        let (mut outpoints, mut amounts, mut scripts, mut sequences) = (Vec::new(), Vec::new(), Vec::new(), Vec::new());
        for (i, prev) in tx.input.iter().zip(prevouts) {
            outpoints.extend_from_slice(&i.previous_output.txid.to_bytes());
            outpoints.extend_from_slice(&i.previous_output.vout.to_le_bytes());
            amounts.extend_from_slice(&prev.value.to_le_bytes());
            write_var_bytes(&mut scripts, &prev.script_pubkey);
            sequences.extend_from_slice(&i.sequence.to_le_bytes());
        }
        msg.extend_from_slice(&sha256(&outpoints));
        msg.extend_from_slice(&sha256(&amounts));
        msg.extend_from_slice(&sha256(&scripts));
        msg.extend_from_slice(&sha256(&sequences));
    }
    if output_type == SIGHASH_ALL {
        let mut outputs = Vec::new();
        for o in &tx.output {
            write_output(&mut outputs, o);
        }
        msg.extend_from_slice(&sha256(&outputs));
    }
    msg.push(0x00);
    if anyone_can_pay {
        msg.extend_from_slice(&txin.previous_output.txid.to_bytes());
        msg.extend_from_slice(&txin.previous_output.vout.to_le_bytes());
        msg.extend_from_slice(&prevouts[input].value.to_le_bytes());
        write_var_bytes(&mut msg, &prevouts[input].script_pubkey);
        msg.extend_from_slice(&txin.sequence.to_le_bytes());
    } else {
        msg.extend_from_slice(&(input as u32).to_le_bytes());
    }
    if output_type == SIGHASH_SINGLE {
        let mut single = Vec::new();
        write_output(&mut single, &tx.output[input]);
        msg.extend_from_slice(&sha256(&single));
    }
    let mut tagged = Vec::with_capacity(1 + msg.len());
    tagged.push(0x00);
    tagged.extend_from_slice(&msg);
    Ok(tagged_hash("TapSighash", &tagged))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sign;
    use secp256k1::{SecretKey, XOnlyPublicKey, schnorr};

    fn secret(hex: &str) -> SecretKey {
        SecretKey::from_secret_bytes(hex::decode(hex).unwrap().try_into().unwrap()).unwrap()
    }

    #[test]
    fn the_bip143_native_example() {
        let unsigned = Transaction::from_hex("0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000").unwrap();
        let hash: [u8; 20] = hex::decode("1d0f172a0ecb48aee1be1f2687d2963ae33f71a1").unwrap().try_into().unwrap();
        let digest = p2wpkh(&unsigned, 1, &hash, 600_000_000).unwrap();
        assert_eq!(hex::encode(digest), "c37af31116d1b27caf68aae9e3ac82f1477929014d5b917657d0eb49478cb670");
        let key1 = secret("619c335025c7f4012e556c2a58b2506e30b8511b53ade95ea316fd8c3286feb9");
        let sig1 = sign::ecdsa_sighash_all(&digest, &key1);
        assert_eq!(hex::encode(&sig1), "304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee01");

        let p2pk = hex::decode("2103c9f4836b9a4f77fc0d81f7bcb01b7f1b35916864b9476c241ce9fc198bd25432ac").unwrap();
        let digest0 = legacy(&unsigned, 0, &p2pk).unwrap();
        let key0 = secret("bbc27228ddcb9209d7fd6f36b02f7dfa6252af40bb2f1cbc7a557da8027ff866");
        let sig0 = sign::ecdsa_sighash_all(&digest0, &key0);

        let mut signed = unsigned.clone();
        script::push(&mut signed.input[0].script_sig, &sig0);
        signed.input[1].witness = vec![sig1, key1.public_key().serialize().to_vec()];
        assert_eq!(
            signed.to_hex(),
            "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000"
        );
    }

    #[test]
    fn the_bip143_nested_example() {
        let unsigned = Transaction::from_hex("0100000001db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a54770100000000feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac92040000").unwrap();
        let key = secret("eb696a065ef48a2192da5b28b694f87544b30fae8327c4510137a922f32c6dcf");
        let pubkey = key.public_key().serialize();
        assert_eq!(hex::encode(pubkey), "03ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a26873");
        let digest = p2wpkh(&unsigned, 0, &crate::hash160(&pubkey), 1_000_000_000).unwrap();
        assert_eq!(hex::encode(digest), "64f3b0f4dd2bb3aa1ce8566d220cc74dda9df97d8490cc81d89d735c92e59fb6");
        let sig = sign::ecdsa_sighash_all(&digest, &key);
        assert_eq!(hex::encode(&sig), "3044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb01");
        let mut signed = unsigned;
        signed.input[0].script_sig = script::p2sh_p2wpkh_script_sig(&pubkey);
        signed.input[0].witness = vec![sig, pubkey.to_vec()];
        assert_eq!(
            signed.to_hex(),
            "01000000000101db6b1b20aa0fd7b23880be2ecbd4a98130974cf4748fb66092ac4d3ceb1a5477010000001716001479091972186c449eb1ded22b78e40d009bdf0089feffffff02b8b4eb0b000000001976a914a457b684d7f0d539a46a45bbc043f35b59d0d96388ac0008af2f000000001976a914fd270b1ee6abcaea97fea7ad0402e8bd8ad6d77c88ac02473044022047ac8e878352d3ebbde1c94ce3a10d057c24175747116f8288e5d794d12d482f0220217f36a485cae903c713331d877c1f64677e3622ad4010726870540656fe9dcb012103ad1d8e89212f0b92c74d23bb710c00662ad1470198ac48c43f7d6f93a2a2687392040000"
        );
    }

    #[test]
    fn the_bip341_key_path_vectors() {
        let tx = Transaction::from_hex("02000000097de20cbff686da83a54981d2b9bab3586f4ca7e48f57f5b55963115f3b334e9c010000000000000000d7b7cab57b1393ace2d064f4d4a2cb8af6def61273e127517d44759b6dafdd990000000000fffffffff8e1f583384333689228c5d28eac13366be082dc57441760d957275419a418420000000000fffffffff0689180aa63b30cb162a73c6d2a38b7eeda2a83ece74310fda0843ad604853b0100000000feffffffaa5202bdf6d8ccd2ee0f0202afbbb7461d9264a25e5bfd3c5a52ee1239e0ba6c0000000000feffffff956149bdc66faa968eb2be2d2faa29718acbfe3941215893a2a3446d32acd050000000000000000000e664b9773b88c09c32cb70a2a3e4da0ced63b7ba3b22f848531bbb1d5d5f4c94010000000000000000e9aa6b8e6c9de67619e6a3924ae25696bb7b694bb677a632a74ef7eadfd4eabf0000000000ffffffffa778eb6a263dc090464cd125c466b5a99667720b1c110468831d058aa1b82af10100000000ffffffff0200ca9a3b000000001976a91406afd46bcdfd22ef94ac122aa11f241244a37ecc88ac807840cb0000000020ac9a87f5594be208f8532db38cff670c450ed2fea8fcdefcc9a663f78bab962b0065cd1d").unwrap();
        let prevouts: Vec<TxOut> = [
            (420_000_000u64, "512053a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"),
            (462_000_000, "5120147c9c57132f6e7ecddba9800bb0c4449251c92a1e60371ee77557b6620f3ea3"),
            (294_000_000, "76a914751e76e8199196d454941c45d1b3a323f1433bd688ac"),
            (504_000_000, "5120e4d810fd50586274face62b8a807eb9719cef49c04177cc6b76a9a4251d5450e"),
            (630_000_000, "512091b64d5324723a985170e4dc5a0f84c041804f2cd12660fa5dec09fc21783605"),
            (378_000_000, "00147dd65592d0ab2fe0d0257d571abf032cd9db93dc"),
            (672_000_000, "512075169f4001aa68f15bbed28b218df1d0a62cbbcf1188c6665110c293c907b831"),
            (546_000_000, "5120712447206d7a5238acc7ff53fbe94a3b64539ad291c7cdbc490b7577e4b17df5"),
            (588_000_000, "512077e30a5522dd9f894c3f8b8bd4c4b2cf82ca7da8a3ea6a239655c39c050ab220"),
        ]
        .iter()
        .map(|(value, spk)| TxOut { value: *value, script_pubkey: hex::decode(spk).unwrap() })
        .collect();

        let cases: &[(usize, u8, &str, &str, &str, &str, &str, &str, &str)] = &[
            (0, 0x03, "6b973d88838f27366ed61c9ad6367663045cb456e28335c109e30717ae0c6baa", "d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d", "", "b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70", "2405b971772ad26915c8dcdf10f238753a9b837e5f8e6a86fd7c0cce5b7296d9", "2514a6272f85cfa0f45eb907fcb0d121b808ed37c6ea160a5a9046ed5526d555", "ed7c1647cb97379e76892be0cacff57ec4a7102aa24296ca39af7541246d8ff14d38958d4cc1e2e478e4d4a764bbfd835b16d4e314b72937b29833060b87276c03"),
            (1, 0x83, "1e4da49f6aaf4e5cd175fe08a32bb5cb4863d963921255f33d3bc31e1343907f", "187791b6f712a8ea41c8ecdd0ee77fab3e85263b37e1ec18a3651926b3a6cf27", "5b75adecf53548f3ec6ad7d78383bf84cc57b55a3127c72b9a2481752dd88b21", "cbd8679ba636c1110ea247542cfbd964131a6be84f873f7f3b62a777528ed001", "ea260c3b10e60f6de018455cd0278f2f5b7e454be1999572789e6a9565d26080", "325a644af47e8a5a2591cda0ab0723978537318f10e6a63d4eed783b96a71a4d", "052aedffc554b41f52b521071793a6b88d6dbca9dba94cf34c83696de0c1ec35ca9c5ed4ab28059bd606a4f3a657eec0bb96661d42921b5f50a95ad33675b54f83"),
            (3, 0x01, "d3c7af07da2d54f7a7735d3d0fc4f0a73164db638b2f2f7c43f711f6d4aa7e64", "93478e9488f956df2396be2ce6c5cced75f900dfa18e7dabd2428aae78451820", "c525714a7f49c28aedbbba78c005931a81c234b2f6c99a73e4d06082adc8bf2b", "6af9e28dbf9d6aaf027696e2598a5b3d056f5fd2355a7fd5a37a0e5008132d30", "97323385e57015b75b0339a549c56a948eb961555973f0951f555ae6039ef00d", "bf013ea93474aa67815b1b6cc441d23b64fa310911d991e713cd34c7f5d46669", "ff45f742a876139946a149ab4d9185574b98dc919d2eb6754f8abaa59d18b025637a3aa043b91817739554f4ed2026cf8022dbd83e351ce1fabc272841d2510a01"),
            (4, 0x00, "f36bb07a11e469ce941d16b63b11b9b9120a84d9d87cff2c84a8d4affb438f4e", "e0dfe2300b0dd746a3f8674dfd4525623639042569d829c7f0eed9602d263e6f", "ccbd66c6f7e8fdab47b3a486f59d28262be857f30d4773f2d5ea47f7761ce0e2", "b57bfa183d28eeb6ad688ddaabb265b4a41fbf68e5fed2c72c74de70d5a786f4", "a8e7aa924f0d58854185a490e6c41f6efb7b675c0f3331b7f14b549400b4d501", "4f900a0bae3f1446fd48490c2958b5a023228f01661cda3496a11da502a7f7ef", "b4010dd48a617db09926f729e79c33ae0b4e94b79f04a1ae93ede6315eb3669de185a17d2b0ac9ee09fd4c64b678a0b61a0a86fa888a273c8511be83bfd6810f"),
            (6, 0x02, "415cfe9c15d9cea27d8104d5517c06e9de48e2f986b695e4f5ffebf230e725d8", "55adf4e8967fbd2e29f20ac896e60c3b0f1d5b0efa9d34941b5958c7b0a0312d", "2f6b2c5397b6d68ca18e09a3f05161668ffe93a988582d55c6f07bd5b3329def", "6579138e7976dc13b6a92f7bfd5a2fc7684f5ea42419d43368301470f3b74ed9", "241c14f2639d0d7139282aa6abde28dd8a067baa9d633e4e7230287ec2d02901", "15f25c298eb5cdc7eb1d638dd2d45c97c4c59dcaec6679cfc16ad84f30876b85", "a3785919a2ce3c4ce26f298c3d51619bc474ae24014bcdd31328cd8cfbab2eff3395fa0a16fe5f486d12f22a9cedded5ae74feb4bbe5351346508c5405bcfee002"),
            (7, 0x82, "c7b0e81f0a9a0b0499e112279d718cca98e79a12e2f137c72ae5b213aad0d103", "ee4fe085983462a184015d1f782d6a5f8b9c2b60130aff050ce221ecf3786592", "6c2dc106ab816b73f9d07e3cd1ef2c8c1256f519748e0813e4edd2405d277bef", "9e0517edc8259bb3359255400b23ca9507f2a91cd1e4250ba068b4eafceba4a9", "65b6000cd2bfa6b7cf736767a8955760e62b6649058cbc970b7c0871d786346b", "cd292de50313804dabe4685e83f923d2969577191a3e1d2882220dca88cbeb10", "ea0c6ba90763c2d3a296ad82ba45881abb4f426b3f87af162dd24d5109edc1cdd11915095ba47c3a9963dc1e6c432939872bc49212fe34c632cd3ab9fed429c482"),
            (8, 0x81, "77863416be0d0665e517e1c375fd6f75839544eca553675ef7fdf4949518ebaa", "f9f400803e683727b14f463836e1e78e1c64417638aa066919291a225f0e8dd8", "ab179431c28d3b68fb798957faf5497d69c883c6fb1e1cd9f81483d87bac90cc", "639f0281b7ac49e742cd25b7f188657626da1ad169209078e2761cefd91fd65e", "ec18ce6af99f43815db543f47b8af5ff5df3b2cb7315c955aa4a86e8143d2bf5", "cccb739eca6c13a8a89e6e5cd317ffe55669bbda23f2fd37b0f18755e008edd2", "bbc9584a11074e83bc8c6759ec55401f0ae7b03ef290c3139814f545b58a9f8127258000874f44bc46db7646322107d4d86aec8e73b8719a61fff761d75b5dd981"),
        ];
        for (input, hash_type, internal_secret, internal_key, merkle_root, tweak, tweaked_secret, digest, witness) in cases {
            let key = secret(internal_secret);
            let (internal, _) = key.x_only_public_key();
            assert_eq!(hex::encode(internal.to_byte_array()), *internal_key, "input {input}");
            let root: Option<[u8; 32]> = (!merkle_root.is_empty()).then(|| hex::decode(merkle_root).unwrap().try_into().unwrap());
            assert_eq!(hex::encode(sign::taproot_tweak(&internal, root.as_ref()).to_be_bytes()), *tweak, "input {input}");
            let keypair = sign::tweaked_keypair(&key, root.as_ref());
            assert_eq!(hex::encode(keypair.to_secret_bytes()), *tweaked_secret, "input {input}");
            assert_eq!(
                &keypair.x_only_public_key().0.to_byte_array()[..],
                &prevouts[*input].script_pubkey[2..],
                "input {input}: the tweaked key is the output's"
            );
            let got = taproot(&tx, *input, &prevouts, *hash_type).unwrap();
            assert_eq!(hex::encode(got), *digest, "input {input}");
          
            let witness = hex::decode(witness).unwrap();
            let (sig, rest) = witness.split_at(64);
            let tail: Vec<u8> = if *hash_type == 0 { Vec::new() } else { vec![*hash_type] };
            assert_eq!(rest, &tail[..]);
            let sig = schnorr::Signature::from_byte_array(sig.try_into().unwrap());
            let output_key =
                XOnlyPublicKey::from_byte_array(prevouts[*input].script_pubkey[2..].try_into().unwrap()).unwrap();
            assert!(sig.verify(&got, &output_key).is_ok(), "input {input}");
          
            let ours = schnorr::sign_with_aux_rand(&got, &keypair, &[0u8; 32]);
            assert_eq!(&ours.to_byte_array()[..], &witness[..64], "input {input}");
        }
        assert!(taproot(&tx, 0, &prevouts, 0x04).is_err());
        assert!(taproot(&tx, 0, &prevouts[..8], 0x00).is_err());
        assert!(taproot(&tx, 9, &prevouts, 0x00).is_err());
        assert!(taproot(&tx, 2, &prevouts, SIGHASH_SINGLE).is_err(), "two outputs, input 2");
    }

    #[test]
    fn an_input_out_of_range_is_refused() {
        let tx = Transaction { version: 2, lock_time: 0, input: vec![], output: vec![] };
        assert!(legacy(&tx, 0, &[]).is_err());
        assert!(p2wpkh(&tx, 0, &[0; 20], 0).is_err());
        assert!(taproot_key_spend(&tx, 0, &[]).is_err());
    }
}
