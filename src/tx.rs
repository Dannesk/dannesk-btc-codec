
use std::fmt;
use std::str::FromStr;

use crate::sha256d;

pub const SEQUENCE_RBF: u32 = 0xffff_fffd;
pub const SEQUENCE_FINAL: u32 = 0xffff_ffff;

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct Txid([u8; 32]);

impl Txid {
    pub fn from_bytes(bytes: [u8; 32]) -> Txid {
        Txid(bytes)
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for Txid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut reversed = self.0;
        reversed.reverse();
        f.write_str(&hex::encode(reversed))
    }
}

impl fmt::Debug for Txid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Txid({self})")
    }
}

impl FromStr for Txid {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let mut bytes: [u8; 32] = hex::decode(s)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| "a txid is 64 hex digits".to_string())?;
        bytes.reverse();
        Ok(Txid(bytes))
    }
}


#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct BlockHash([u8; 32]);

impl BlockHash {
    pub fn from_bytes(bytes: [u8; 32]) -> BlockHash {
        BlockHash(bytes)
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0
    }
}

impl fmt::Display for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut reversed = self.0;
        reversed.reverse();
        f.write_str(&hex::encode(reversed))
    }
}

impl fmt::Debug for BlockHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlockHash({self})")
    }
}

impl FromStr for BlockHash {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, String> {
        let mut bytes: [u8; 32] = hex::decode(s)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or_else(|| "a block hash is 64 hex digits".to_string())?;
        bytes.reverse();
        Ok(BlockHash(bytes))
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OutPoint {
    pub txid: Txid,
    pub vout: u32,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxIn {
    pub previous_output: OutPoint,
    pub script_sig: Vec<u8>,
    pub sequence: u32,
    pub witness: Vec<Vec<u8>>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct TxOut {
    /// Satoshis.
    pub value: u64,
    pub script_pubkey: Vec<u8>,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Transaction {
    pub version: i32,
    pub lock_time: u32,
    pub input: Vec<TxIn>,
    pub output: Vec<TxOut>,
}

impl Transaction {
  
    pub fn serialize(&self) -> Vec<u8> {
        self.encode(self.has_witness() || self.input.is_empty())
    }

    pub fn serialize_without_witness(&self) -> Vec<u8> {
        self.encode(false)
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.serialize())
    }

    pub fn has_witness(&self) -> bool {
        self.input.iter().any(|i| !i.witness.is_empty())
    }

    pub fn txid(&self) -> Txid {
        Txid(sha256d(&self.serialize_without_witness()))
    }

    pub fn wtxid(&self) -> Txid {
        Txid(sha256d(&self.serialize()))
    }

    pub fn weight(&self) -> u64 {
        let base = self.serialize_without_witness().len() as u64;
        let total = if self.has_witness() { self.encode(true).len() as u64 } else { base };
        base * 3 + total
    }

    pub fn vsize(&self) -> u64 {
        self.weight().div_ceil(4)
    }

    fn encode(&self, witness: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(10 + self.input.len() * 150 + self.output.len() * 43);
        out.extend_from_slice(&self.version.to_le_bytes());
        if witness {
            out.extend_from_slice(&[0x00, 0x01]);
        }
        write_varint(&mut out, self.input.len() as u64);
        for input in &self.input {
            out.extend_from_slice(&input.previous_output.txid.0);
            out.extend_from_slice(&input.previous_output.vout.to_le_bytes());
            write_var_bytes(&mut out, &input.script_sig);
            out.extend_from_slice(&input.sequence.to_le_bytes());
        }
        write_varint(&mut out, self.output.len() as u64);
        for output in &self.output {
            write_output(&mut out, output);
        }
        if witness {
            for input in &self.input {
                write_varint(&mut out, input.witness.len() as u64);
                for item in &input.witness {
                    write_var_bytes(&mut out, item);
                }
            }
        }
        out.extend_from_slice(&self.lock_time.to_le_bytes());
        out
    }


    pub fn deserialize(bytes: &[u8]) -> Result<Transaction, String> {
        let mut r = Reader { bytes, pos: 0 };
        let tx = Transaction::read(&mut r)?;
        r.finish("the transaction")?;
        Ok(tx)
    }

    fn read(r: &mut Reader<'_>) -> Result<Transaction, String> {
        let version = r.u32()? as i32;
        let mut count = r.varint()?;
        let mut segwit = false;
        if count == 0 {
          
            if r.u8()? != 1 {
                return Err("unknown witness flag".to_string());
            }
            segwit = true;
            count = r.varint()?;
        }
        let mut input = Vec::with_capacity(r.at_most(count, 41)?);
        for _ in 0..count {
            let mut txid = [0u8; 32];
            txid.copy_from_slice(r.take(32)?);
            let vout = r.u32()?;
            let script_sig = r.var_bytes()?.to_vec();
            let sequence = r.u32()?;
            input.push(TxIn { previous_output: OutPoint { txid: Txid(txid), vout }, script_sig, sequence, witness: Vec::new() });
        }
        let count = r.varint()?;
        let mut output = Vec::with_capacity(r.at_most(count, 9)?);
        for _ in 0..count {
            let value = r.u64()?;
            let script_pubkey = r.var_bytes()?.to_vec();
            output.push(TxOut { value, script_pubkey });
        }
        if segwit {
            for txin in &mut input {
                let count = r.varint()?;
                let mut witness = Vec::with_capacity(r.at_most(count, 1)?);
                for _ in 0..count {
                    witness.push(r.var_bytes()?.to_vec());
                }
                txin.witness = witness;
            }
            if !input.is_empty() && !input.iter().any(|i| !i.witness.is_empty()) {
                return Err("the witness flag is set but no input has a witness".to_string());
            }
        }
        let lock_time = r.u32()?;
        Ok(Transaction { version, lock_time, input, output })
    }

    pub fn from_hex(s: &str) -> Result<Transaction, String> {
        Transaction::deserialize(&hex::decode(s).map_err(|e| format!("not hex: {e}"))?)
    }
}


#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Header {
    pub version: i32,
    pub prev_blockhash: [u8; 32],
    pub merkle_root: [u8; 32],
    pub time: u32,
    pub bits: u32,
    pub nonce: u32,
}

impl Header {
    pub fn serialize(&self) -> [u8; 80] {
        let mut out = [0u8; 80];
        out[..4].copy_from_slice(&self.version.to_le_bytes());
        out[4..36].copy_from_slice(&self.prev_blockhash);
        out[36..68].copy_from_slice(&self.merkle_root);
        out[68..72].copy_from_slice(&self.time.to_le_bytes());
        out[72..76].copy_from_slice(&self.bits.to_le_bytes());
        out[76..80].copy_from_slice(&self.nonce.to_le_bytes());
        out
    }

    pub fn block_hash(&self) -> BlockHash {
        BlockHash(sha256d(&self.serialize()))
    }

    fn read(r: &mut Reader<'_>) -> Result<Header, String> {
        let version = r.u32()? as i32;
        let mut prev_blockhash = [0u8; 32];
        prev_blockhash.copy_from_slice(r.take(32)?);
        let mut merkle_root = [0u8; 32];
        merkle_root.copy_from_slice(r.take(32)?);
        Ok(Header { version, prev_blockhash, merkle_root, time: r.u32()?, bits: r.u32()?, nonce: r.u32()? })
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Block {
    pub header: Header,
    pub txdata: Vec<Transaction>,
}

impl Block {
    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(80 + 9 + self.txdata.len() * 250);
        out.extend_from_slice(&self.header.serialize());
        write_varint(&mut out, self.txdata.len() as u64);
        for tx in &self.txdata {
            out.extend_from_slice(&tx.serialize());
        }
        out
    }

    pub fn to_hex(&self) -> String {
        hex::encode(self.serialize())
    }

    pub fn deserialize(bytes: &[u8]) -> Result<Block, String> {
        let mut r = Reader { bytes, pos: 0 };
        let header = Header::read(&mut r)?;
        let count = r.varint()?;
        let mut txdata = Vec::with_capacity(r.at_most(count, 10)?);
        for _ in 0..count {
            txdata.push(Transaction::read(&mut r)?);
        }
        r.finish("the block")?;
        Ok(Block { header, txdata })
    }

    pub fn from_hex(s: &str) -> Result<Block, String> {
        Block::deserialize(&hex::decode(s).map_err(|e| format!("not hex: {e}"))?)
    }

    pub fn block_hash(&self) -> BlockHash {
        self.header.block_hash()
    }

    pub fn merkle_root(&self) -> [u8; 32] {
        let mut level: Vec<[u8; 32]> = self.txdata.iter().map(|tx| tx.txid().to_bytes()).collect();
        if level.is_empty() {
            return [0; 32];
        }
        while level.len() > 1 {
            if level.len() % 2 == 1 {
                level.push(*level.last().expect("not empty"));
            }
            level = level
                .chunks(2)
                .map(|pair| {
                    let mut joined = [0u8; 64];
                    joined[..32].copy_from_slice(&pair[0]);
                    joined[32..].copy_from_slice(&pair[1]);
                    sha256d(&joined)
                })
                .collect();
        }
        level[0]
    }
}

pub(crate) fn write_varint(out: &mut Vec<u8>, n: u64) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&n.to_le_bytes());
        }
    }
}

pub(crate) fn write_var_bytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

pub(crate) fn write_output(out: &mut Vec<u8>, output: &TxOut) {
    out.extend_from_slice(&output.value.to_le_bytes());
    write_var_bytes(out, &output.script_pubkey);
}

struct Reader<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(n).filter(|&end| end <= self.bytes.len());
        let end = end.ok_or_else(|| "the transaction ends early".to_string())?;
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn u8(&mut self) -> Result<u8, String> {
        Ok(self.take(1)?[0])
    }

    fn u32(&mut self) -> Result<u32, String> {
        Ok(u32::from_le_bytes(self.take(4)?.try_into().expect("four bytes")))
    }

    fn u64(&mut self) -> Result<u64, String> {
        Ok(u64::from_le_bytes(self.take(8)?.try_into().expect("eight bytes")))
    }

    fn varint(&mut self) -> Result<u64, String> {
        let (n, least) = match self.u8()? {
            0xfd => (u16::from_le_bytes(self.take(2)?.try_into().expect("two bytes")) as u64, 0xfd),
            0xfe => (self.u32()? as u64, 0x1_0000),
            0xff => (self.u64()?, 0x1_0000_0000),
            n => return Ok(n as u64),
        };
        if n < least {
            return Err("a count is not in its shortest form".to_string());
        }
        Ok(n)
    }

    fn var_bytes(&mut self) -> Result<&'a [u8], String> {
        let len = self.varint()?;
        self.take(usize::try_from(len).map_err(|_| "a length does not fit".to_string())?)
    }

    fn finish(&self, what: &str) -> Result<(), String> {
        if self.pos != self.bytes.len() {
            return Err(format!("{} bytes left after {what}", self.bytes.len() - self.pos));
        }
        Ok(())
    }

   
    fn at_most(&self, count: u64, min_size: usize) -> Result<usize, String> {
        let left = (self.bytes.len() - self.pos) as u64;
        if count > left / min_size as u64 {
            return Err("a count exceeds the bytes left".to_string());
        }
        Ok(count as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    
    const BIP143_UNSIGNED: &str = "0100000002fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f0000000000eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac11000000";
    const BIP143_SIGNED: &str = "01000000000102fff7f7881a8099afa6940d42d1e7f6362bec38171ea3edf433541db4e4ad969f00000000494830450221008b9d1dc26ba6a9cb62127b02742fa9d754cd3bebf337f7a55d114c8e5cdd30be022040529b194ba3f9281a99f2b1c0a19c0489bc22ede944ccf4ecbab4cc618ef3ed01eeffffffef51e1b804cc89d182d279655c3aa89e815b1b309fe287d9b2b55d57b90ec68a0100000000ffffffff02202cb206000000001976a9148280b37df378db99f66f85c95a783a76ac7a6d5988ac9093510d000000001976a9143bde42dbee7e4dbe6a21b2d50ce2f0167faa815988ac000247304402203609e17b84f6a7d30c80bfa610b5b4542f32a8a0d5447a12fb1366d7f01cc44a0220573a954c4518331561406f90300e8f3358f51928d43c212a8caed02de67eebee0121025476c2e83188368da1ff3e292e7acafcdb3566bb0ad253f62fc70f07aeee635711000000";

    #[test]
    fn the_bip143_transactions_round_trip() {
        let unsigned = Transaction::from_hex(BIP143_UNSIGNED).unwrap();
        assert_eq!(unsigned.version, 1);
        assert_eq!(unsigned.lock_time, 17);
        assert_eq!(unsigned.input.len(), 2);
        assert_eq!(unsigned.input[0].sequence, 0xffff_ffee);
        assert_eq!(unsigned.output[0].value, 112_340_000);
        assert_eq!(unsigned.output[1].value, 223_450_000);
        assert!(!unsigned.has_witness());
        assert_eq!(unsigned.to_hex(), BIP143_UNSIGNED);
        assert_eq!(unsigned.weight(), 4 * unsigned.serialize().len() as u64);

        let signed = Transaction::from_hex(BIP143_SIGNED).unwrap();
        assert!(signed.has_witness());
        assert!(signed.input[0].witness.is_empty());
        assert_eq!(signed.input[1].witness.len(), 2);
        assert_eq!(signed.to_hex(), BIP143_SIGNED);
       
        let mut stripped = signed.clone();
        stripped.input[0].script_sig.clear();
        stripped.input[1].witness.clear();
        assert_eq!(stripped.txid(), unsigned.txid());
        assert_ne!(signed.wtxid(), signed.txid());
    }

  
    #[test]
    fn the_wallets_transaction_measures_the_same() {
        let signed = Transaction::from_hex("0200000000010411111111111111111111111111111111111111111111111111111111111111110000000000fdffffff12121212121212121212121212121212121212121212121212121212121212120100000000fdffffff13131313131313131313131313131313131313131313131313131313131313130200000017160014f990679acafe25c27615373b40bf22446d24ff44fdffffff1414141414141414141414141414141414141414141414141414141414141414030000006a473044022076e3772f3ad10c012e557de5f9484746a1c5678edad4efd1bc121652a1a92d230220691d389995b38a8cde0076db8330ce6637e8ca5b2702095262d75d3a952f06b9012103aaeb52dd7494c361049de67cc680e83ebcbbbdbeb13637d92cd845f70308af5efdffffff02a086010000000000160014751e76e8199196d454941c45d1b3a323f1433bd6a686010000000000160014c0cebcd6c3d3ca8c75dc5ec62ebe55330ef910e20247304402206b66a37ac3655b0f34a15adc2709fc8476fde36c9e1ee8f67063c4b6e588e57e022016c93e2e92fc172178f1e21a17608b778072e1d8cab2714c4cf8b4bc08e9ef2701210330d54fd0dd420a6e5f8d3624f5f3482cae350f79d5f0753bf5beef9c2d91af3c014001cd1e375030830678fce7fafd63243a462548d36c06c05b38978c75ab1e53f06e4083976711d082281116a9d733e2326731c8846275520c459dfae2c9acc8bf0247304402201ecd50029a61a940fd3a6e43b74963d37f86f7bef9ca10bb237c7ab117e8e201022079c726041f676ff016688faa00960c01442783c3a0adefca1e9a0c9d7a8770db0121039b3b694b8fc5b5e07fb069c783cac754f5d38c3e08bed1960e31fdb1dda35c240000000000").unwrap();
        assert_eq!(signed.txid().to_string(), "dcb9559e17ad9ea1d6e26263ad8086b020730288d2aad53713d92b0add4eead8");
        assert_eq!(signed.wtxid().to_string(), "583f04c43e0917e4047865f524f0b1caff90a23990734a3e1eb97e831cb6eea3");
        assert_eq!(signed.vsize(), 436);
        assert_eq!(signed.weight(), 1743);
        assert_eq!(signed.input[1].witness.len(), 1, "a key-path spend is one signature");
        assert_eq!(signed.input[3].witness.len(), 0, "legacy has no witness");
        assert_eq!(signed.input[2].script_sig.len(), 23, "nested segwit pushes the redeem script");
    }

    #[test]
    fn txids_print_reversed() {
        let id: Txid = "dcb9559e17ad9ea1d6e26263ad8086b020730288d2aad53713d92b0add4eead8".parse().unwrap();
        assert_eq!(id.to_bytes()[0], 0xd8);
        assert_eq!(id.to_string(), "dcb9559e17ad9ea1d6e26263ad8086b020730288d2aad53713d92b0add4eead8");
        assert_eq!(format!("{id:?}"), "Txid(dcb9559e17ad9ea1d6e26263ad8086b020730288d2aad53713d92b0add4eead8)");
        assert!("3e05".parse::<Txid>().is_err());
        assert!("zz".repeat(32).parse::<Txid>().is_err());
    }

    #[test]
    fn malformed_bytes_are_refused() {
        let good = hex::decode(BIP143_SIGNED).unwrap();
        assert!(Transaction::deserialize(&good[..good.len() - 1]).is_err(), "truncated");
        let mut long = good.clone();
        long.push(0);
        assert!(Transaction::deserialize(&long).is_err(), "trailing byte");
        let mut flag = good.clone();
        flag[5] = 2;
        assert!(Transaction::deserialize(&flag).is_err(), "unknown flag");
        assert!(Transaction::deserialize(&[]).is_err());
        let mut padded = hex::decode(BIP143_UNSIGNED).unwrap();
        padded.splice(4..5, [0xfd, 0x02, 0x00]);
        assert!(Transaction::deserialize(&padded).is_err(), "non-canonical count");
        let mut empty = hex::decode(BIP143_UNSIGNED).unwrap();
        empty.splice(4..4, [0x00, 0x01]);
        let lock = empty.len() - 4;
        empty.splice(lock..lock, [0x00, 0x00]);
        assert!(Transaction::deserialize(&empty).is_err(), "witness flag without witness");
    }

    #[test]
    fn the_genesis_header_hashes_to_its_block_hash() {
        let header = Header {
            version: 1,
            prev_blockhash: [0; 32],
            merkle_root: "4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b".parse::<Txid>().unwrap().to_bytes(),
            time: 1_231_006_505,
            bits: 0x1d00_ffff,
            nonce: 2_083_236_893,
        };
        assert_eq!(
            hex::encode(header.serialize()),
            "0100000000000000000000000000000000000000000000000000000000000000000000003ba3edfd7a7b12b27ac72c3e67768f617fc81bc3888a51323a9fb8aa4b1e5e4a29ab5f49ffff001d1dac2b7c"
        );
        let hash = header.block_hash();
        assert_eq!(hash.to_string(), "000000000019d6689c085ae165831e934ff763ae46a2a6c172b3f1b60a8ce26f");
        assert_eq!(hash.to_string().parse::<BlockHash>().unwrap(), hash);
        assert_eq!(format!("{hash:?}"), format!("BlockHash({hash})"));
    }

  
    #[test]
    fn blocks_round_trip_and_root_their_transactions() {
        let tx = |n: u8| Transaction {
            version: 2,
            lock_time: 0,
            input: vec![],
            output: vec![TxOut { value: n as u64, script_pubkey: vec![0x00, 0x14, n] }],
        };
        let mut block = Block {
            header: Header { version: 2, prev_blockhash: [7; 32], merkle_root: [0; 32], time: 0, bits: 0, nonce: 0 },
            txdata: vec![tx(1)],
        };
        assert_eq!(block.merkle_root(), tx(1).txid().to_bytes());
        block.txdata.push(tx(2));
        let mut pair = [0u8; 64];
        pair[..32].copy_from_slice(&tx(1).txid().to_bytes());
        pair[32..].copy_from_slice(&tx(2).txid().to_bytes());
        assert_eq!(block.merkle_root(), sha256d(&pair));
        block.txdata.push(tx(3));
        let mut odd = [0u8; 64];
        odd[..32].copy_from_slice(&tx(3).txid().to_bytes());
        odd[32..].copy_from_slice(&tx(3).txid().to_bytes());
        let mut top = [0u8; 64];
        top[..32].copy_from_slice(&sha256d(&pair));
        top[32..].copy_from_slice(&sha256d(&odd));
        assert_eq!(block.merkle_root(), sha256d(&top));
        block.header.merkle_root = block.merkle_root();

        let bytes = block.serialize();
        assert_eq!(bytes.len(), 80 + 1 + 3 * tx(1).serialize().len());
        assert_eq!(Block::deserialize(&bytes).unwrap(), block);
        assert_eq!(Block::from_hex(&block.to_hex()).unwrap(), block);
        assert_eq!(block.block_hash(), block.header.block_hash());
        let mut long = bytes.clone();
        long.push(0);
        assert!(Block::deserialize(&long).is_err(), "trailing byte");
        assert!(Block::deserialize(&bytes[..100]).is_err(), "truncated");
        assert!(Block::deserialize(&[]).is_err());
    }

    #[test]
    fn counts_take_the_shortest_form() {
        let mut out = Vec::new();
        for n in [0u64, 0xfc, 0xfd, 0xffff, 0x1_0000, 0xffff_ffff, 0x1_0000_0000] {
            write_varint(&mut out, n);
        }
        assert_eq!(
            hex::encode(&out),
            "00fcfdfd00fdfffffe00000100feffffffffff0000000001000000"
        );
        let mut r = Reader { bytes: &out, pos: 0 };
        for n in [0u64, 0xfc, 0xfd, 0xffff, 0x1_0000, 0xffff_ffff, 0x1_0000_0000] {
            assert_eq!(r.varint().unwrap(), n);
        }
    }
}
