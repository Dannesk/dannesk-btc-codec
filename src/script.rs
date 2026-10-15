

use crate::hash160;

pub const OP_0: u8 = 0x00;
pub const OP_PUSHDATA1: u8 = 0x4c;
pub const OP_PUSHDATA2: u8 = 0x4d;
pub const OP_1: u8 = 0x51;
pub const OP_16: u8 = 0x60;
pub const OP_DUP: u8 = 0x76;
pub const OP_EQUAL: u8 = 0x87;
pub const OP_EQUALVERIFY: u8 = 0x88;
pub const OP_HASH160: u8 = 0xa9;
pub const OP_CHECKSIG: u8 = 0xac;


pub fn push(script: &mut Vec<u8>, data: &[u8]) {
    match data.len() {
        0..=75 => script.push(data.len() as u8),
        76..=255 => {
            script.push(OP_PUSHDATA1);
            script.push(data.len() as u8);
        }
        256..=65535 => {
            script.push(OP_PUSHDATA2);
            script.extend_from_slice(&(data.len() as u16).to_le_bytes());
        }
        _ => panic!("a script pushes at most 65535 bytes"),
    }
    script.extend_from_slice(data);
}

pub fn p2pkh(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(25);
    s.extend_from_slice(&[OP_DUP, OP_HASH160]);
    push(&mut s, pubkey_hash);
    s.extend_from_slice(&[OP_EQUALVERIFY, OP_CHECKSIG]);
    s
}

pub fn p2sh(script_hash: &[u8; 20]) -> Vec<u8> {
    let mut s = Vec::with_capacity(23);
    s.push(OP_HASH160);
    push(&mut s, script_hash);
    s.push(OP_EQUAL);
    s
}

pub fn witness(version: u8, program: &[u8]) -> Vec<u8> {
    assert!(version <= 16, "witness versions run 0 to 16");
    let mut s = Vec::with_capacity(2 + program.len());
    s.push(if version == 0 { OP_0 } else { OP_1 + version - 1 });
    push(&mut s, program);
    s
}


pub fn p2wpkh(pubkey_hash: &[u8; 20]) -> Vec<u8> {
    witness(0, pubkey_hash)
}

pub fn p2pkh_script_sig(signature: &[u8], pubkey: &[u8; 33]) -> Vec<u8> {
    let mut s = Vec::with_capacity(2 + signature.len() + 33);
    push(&mut s, signature);
    push(&mut s, pubkey);
    s
}


pub fn p2sh_p2wpkh_script_sig(pubkey: &[u8; 33]) -> Vec<u8> {
    let mut s = Vec::with_capacity(23);
    push(&mut s, &p2wpkh(&hash160(pubkey)));
    s
}


pub fn pushes(script: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut items = Vec::new();
    let mut i = 0;
    while i < script.len() {
        let op = script[i];
        let (len, header) = match op {
            1..=75 => (op as usize, 1),
            OP_PUSHDATA1 => (*script.get(i + 1)? as usize, 2),
            OP_PUSHDATA2 => (u16::from_le_bytes([*script.get(i + 1)?, *script.get(i + 2)?]) as usize, 3),
            _ => return None,
        };
        let start = i + header;
        items.push(script.get(start..start + len)?.to_vec());
        i = start + len;
    }
    Some(items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_output_scripts_are_the_wallets() {
        let hash = |s: &str| -> [u8; 20] { hex::decode(s).unwrap().try_into().unwrap() };
        assert_eq!(
            hex::encode(p2wpkh(&hash("c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2"))),
            "0014c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e2"
        );
        assert_eq!(
            hex::encode(p2sh(&hash("3fb6e95812e57bb4691f9a4a628862a61a4f769b"))),
            "a9143fb6e95812e57bb4691f9a4a628862a61a4f769b87"
        );
        assert_eq!(
            hex::encode(p2pkh(&hash("d986ed01b7a22225a70edbf2ba7cfb63a15cb3aa"))),
            "76a914d986ed01b7a22225a70edbf2ba7cfb63a15cb3aa88ac"
        );
        let key = hex::decode("a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c").unwrap();
        assert_eq!(
            hex::encode(witness(1, &key)),
            "5120a60869f0dbcf1dc659c9cecbaf8050135ea9e8cdc487053f1dc6880949dc684c"
        );
        assert_eq!(hex::encode(witness(16, &[0x75, 0x1e])), "6002751e");
    }

    #[test]
    fn pushes_take_the_shortest_header() {
        let mut s = Vec::new();
        push(&mut s, &[1; 75]);
        push(&mut s, &[2; 76]);
        push(&mut s, &[3; 255]);
        push(&mut s, &[4; 256]);
        assert_eq!(s[0], 75);
        assert_eq!(s[76..78], [OP_PUSHDATA1, 76]);
        assert_eq!(s[154..156], [OP_PUSHDATA1, 255]);
        assert_eq!(s[411..414], [OP_PUSHDATA2, 0x00, 0x01]);
        assert_eq!(pushes(&s).unwrap(), vec![vec![1; 75], vec![2; 76], vec![3; 255], vec![4; 256]]);
        assert_eq!(pushes(&[0x76]), None);
        assert_eq!(pushes(&[0x02, 0x01]), None);
    }

    #[test]
    fn the_script_sigs_carry_what_the_network_evaluates() {
        let pubkey: [u8; 33] =
            hex::decode("039b3b694b8fc5b5e07fb069c783cac754f5d38c3e08bed1960e31fdb1dda35c24").unwrap().try_into().unwrap();
        assert_eq!(
            hex::encode(p2sh_p2wpkh_script_sig(&pubkey)),
            "160014f990679acafe25c27615373b40bf22446d24ff44"
        );
        let sig = [0x30u8; 71];
        let s = p2pkh_script_sig(&sig, &pubkey);
        assert_eq!(pushes(&s).unwrap(), vec![sig.to_vec(), pubkey.to_vec()]);
    }
}
