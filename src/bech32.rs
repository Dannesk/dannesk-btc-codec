

const CHARSET: &[u8; 32] = b"qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GENERATOR: [u32; 5] = [0x3b6a_57b2, 0x2650_8e6d, 0x1ea1_19fa, 0x3d42_33dd, 0x2a14_62b3];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Variant {
    Bech32,
    Bech32m,
}

impl Variant {
    fn constant(self) -> u32 {
        match self {
            Variant::Bech32 => 1,
            Variant::Bech32m => 0x2bc8_30a3,
        }
    }
}


#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Decoded {
    pub hrp: String,
    pub data: Vec<u8>,
    pub variant: Variant,
}

fn polymod(values: impl IntoIterator<Item = u8>) -> u32 {
    let mut chk: u32 = 1;
    for v in values {
        let top = chk >> 25;
        chk = ((chk & 0x01ff_ffff) << 5) ^ v as u32;
        for (i, g) in GENERATOR.iter().enumerate() {
            if (top >> i) & 1 == 1 {
                chk ^= g;
            }
        }
    }
    chk
}

fn hrp_expand(hrp: &str) -> impl Iterator<Item = u8> + '_ {
    hrp.bytes()
        .map(|b| b >> 5)
        .chain(std::iter::once(0))
        .chain(hrp.bytes().map(|b| b & 31))
}


pub fn encode(hrp: &str, data: &[u8], variant: Variant) -> Result<String, String> {
    if hrp.is_empty() || hrp.len() > 83 || !hrp.bytes().all(|b| (33..=126).contains(&b)) {
        return Err("the human-readable part is 1 to 83 printable ASCII characters".to_string());
    }
    if hrp.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err("the human-readable part is encoded in lowercase".to_string());
    }
    if data.iter().any(|&d| d >= 32) {
        return Err("data values are 5 bits".to_string());
    }
    if hrp.len() + 1 + data.len() + 6 > 90 {
        return Err("the string would be longer than 90 characters".to_string());
    }
    let values: Vec<u8> = hrp_expand(hrp).chain(data.iter().copied()).chain([0u8; 6]).collect();
    let pm = polymod(values) ^ variant.constant();
    let mut s = String::with_capacity(hrp.len() + 1 + data.len() + 6);
    s.push_str(hrp);
    s.push('1');
    for &d in data {
        s.push(CHARSET[d as usize] as char);
    }
    for i in 0..6 {
        s.push(CHARSET[((pm >> (5 * (5 - i))) & 31) as usize] as char);
    }
    Ok(s)
}

pub fn decode(s: &str) -> Result<Decoded, String> {
    if !s.is_ascii() || s.len() > 90 {
        return Err("not a bech32 string".to_string());
    }
    if s.bytes().any(|b| b.is_ascii_lowercase()) && s.bytes().any(|b| b.is_ascii_uppercase()) {
        return Err("mixed case".to_string());
    }
    let s = s.to_ascii_lowercase();
    let separator = s.rfind('1').ok_or_else(|| "no separator".to_string())?;
    if separator == 0 {
        return Err("empty human-readable part".to_string());
    }
    if s.len() < separator + 7 {
        return Err("checksum too short".to_string());
    }
    let (hrp, rest) = s.split_at(separator);
    if !hrp.bytes().all(|b| (33..=126).contains(&b)) {
        return Err("character out of range in the human-readable part".to_string());
    }
    let mut data = Vec::with_capacity(rest.len() - 1);
    for c in rest[1..].bytes() {
        let value = CHARSET
            .iter()
            .position(|&x| x == c)
            .ok_or_else(|| format!("'{}' is not a bech32 character", c as char))?;
        data.push(value as u8);
    }
    let variant = match polymod(hrp_expand(hrp).chain(data.iter().copied())) {
        1 => Variant::Bech32,
        0x2bc8_30a3 => Variant::Bech32m,
        _ => return Err("invalid checksum".to_string()),
    };
    data.truncate(data.len() - 6);
    Ok(Decoded { hrp: hrp.to_string(), data, variant })
}


pub fn convert_bits(data: &[u8], from: u32, to: u32, pad: bool) -> Result<Vec<u8>, String> {
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    let max = (1u32 << to) - 1;
    let mut out = Vec::with_capacity(data.len() * from as usize / to as usize + 1);
    for &value in data {
        if (value as u32) >> from != 0 {
            return Err(format!("value {value} does not fit in {from} bits"));
        }
        acc = (acc << from) | value as u32;
        bits += from;
        while bits >= to {
            bits -= to;
            out.push(((acc >> bits) & max) as u8);
        }
    }
    if pad {
        if bits > 0 {
            out.push(((acc << (to - bits)) & max) as u8);
        }
    } else if bits >= from || ((acc << (to - bits)) & max) != 0 {
        return Err("invalid padding".to_string());
    }
    Ok(out)
}


pub fn segwit_encode(hrp: &str, version: u8, program: &[u8]) -> Result<String, String> {
    check_program(version, program)?;
    let mut data = vec![version];
    data.extend(convert_bits(program, 8, 5, true)?);
    let variant = if version == 0 { Variant::Bech32 } else { Variant::Bech32m };
    encode(hrp, &data, variant)
}

pub fn segwit_decode(hrp: &str, s: &str) -> Result<(u8, Vec<u8>), String> {
    let decoded = decode(s)?;
    if decoded.hrp != hrp {
        return Err(format!("not a {hrp} address"));
    }
    let (&version, rest) = decoded.data.split_first().ok_or_else(|| "empty data".to_string())?;
    if version > 16 {
        return Err(format!("witness version {version} is not defined"));
    }
    let program = convert_bits(rest, 5, 8, false)?;
    check_program(version, &program)?;
    let expected = if version == 0 { Variant::Bech32 } else { Variant::Bech32m };
    if decoded.variant != expected {
        return Err("the checksum is the other variant's".to_string());
    }
    Ok((version, program))
}

fn check_program(version: u8, program: &[u8]) -> Result<(), String> {
    if version > 16 {
        return Err(format!("witness version {version} is not defined"));
    }
    if !(2..=40).contains(&program.len()) {
        return Err(format!("a witness program is 2 to 40 bytes, not {}", program.len()));
    }
    if version == 0 && program.len() != 20 && program.len() != 32 {
        return Err(format!("a version 0 program is 20 or 32 bytes, not {}", program.len()));
    }
    Ok(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    const VALID_BECH32: &[&str] = &[
        "A12UEL5L",
        "a12uel5l",
        "an83characterlonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1tt5tgs",
        "abcdef1qpzry9x8gf2tvdw0s3jn54khce6mua7lmqqqxw",
        "11qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqc8247j",
        "split1checkupstagehandshakeupstreamerranterredcaperred2y9e3w",
        "?1ezyfcl",
    ];

    const VALID_BECH32M: &[&str] = &[
        "A1LQFN3A",
        "a1lqfn3a",
        "an83characterlonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11sg7hg6",
        "abcdef1l7aum6echk45nj3s0wdvt2fg8x9yrzpqzd3ryx",
        "11llllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllllludsr8",
        "split1checkupstagehandshakeupstreamerranterredcaperredlc445v",
        "?1v759aa",
    ];

    const INVALID: &[&str] = &[
        " 1nwldj5",
        "\x7f1axkwrx",
        "\u{80}1eym55h",
        "an84characterslonghumanreadablepartthatcontainsthenumber1andtheexcludedcharactersbio1569pvx",
        "pzry9x0s0muk",
        "1pzry9x0s0muk",
        "x1b4n0q5v",
        "li1dgmt3",
        "de1lg7wt\u{ff}",
        "A1G7SGD8",
        "10a06t8",
        "1qzzfhee",
        " 1xj0phk",
        "\x7f1g6xzxy",
        "\u{80}1vctc34",
        "an84characterslonghumanreadablepartthatcontainsthetheexcludedcharactersbioandnumber11d6pts4",
        "qyrz8wqd2c9m",
        "1qyrz8wqd2c9m",
        "y1b0jsk6g",
        "lt1igcx5c0",
        "in1muywd",
        "mm1crxm3i",
        "au1s5cgom",
        "M1VUXWEZ",
        "16plkw9",
        "1p2gdwpf",
    ];

    /// BIP-350's valid addresses and their scripts.
    pub(crate) const VALID_ADDRESSES: &[(&str, &str)] = &[
        ("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4", "0014751e76e8199196d454941c45d1b3a323f1433bd6"),
        ("tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sl5k7", "00201863143c14c5166804bd19203356da136c985678cd4d27a1b8c6329604903262"),
        ("bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kt5nd6y", "5128751e76e8199196d454941c45d1b3a323f1433bd6751e76e8199196d454941c45d1b3a323f1433bd6"),
        ("BC1SW50QGDZ25J", "6002751e"),
        ("bc1zw508d6qejxtdg4y5r3zarvaryvaxxpcs", "5210751e76e8199196d454941c45d1b3a323"),
        ("tb1qqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesrxh6hy", "0020000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
        ("tb1pqqqqp399et2xygdj5xreqhjjvcmzhxw4aywxecjdzew6hylgvsesf3hn0c", "5120000000c4a5cad46221b2a187905e5266362b99d5e91c6ce24d165dab93e86433"),
        ("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0", "512079be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
    ];

    /// BIP-350's invalid addresses, with BIP-173's that it does not repeat.
    pub(crate) const INVALID_ADDRESSES: &[&str] = &[
        "tc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq5zuyut",
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
        "tb1z0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqglt7rf",
        "BC1S0XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ54WELL",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kemeawh",
        "tb1q0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq24jc47",
        "bc1p38j9r5y49hruaue7wxjce0updqjuyyx0kh56v8s25huc6995vvpql3jow4",
        "BC130XLXVLHEMJA6C4DQV22UAPCTQUPFHLXM9H8Z3K2E72Q4K9HCZ7VQ7ZWS8R",
        "bc1pw5dgrnzv",
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v8n0nx0muaewav253zgeav",
        "BC1QR508D6QEJXTDG4Y5R3ZARVARYV98GJ9P",
        "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vq47Zagq",
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7v07qwwzcrf",
        "tb1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vpggkg4j",
        "bc1gmk9yu",
        "tc1qw508d6qejxtdg4y5r3zarvary0c5xw7kg3g4ty",
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5",
        "BC13W508D6QEJXTDG4Y5R3ZARVARY0C5XW7KN40WF2",
        "bc1rw5uspcuh",
        "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7kw5rljs90",
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3q0sL5k7",
        "bc1zw508d6qejxtdg4y5r3zarvaryvqyzf3du",
        "tb1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3pjxtptv",
        // BIP-173's version 1 address with a bech32 checksum: valid then,
        // not since BIP-350.
        "bc1pw508d6qejxtdg4y5r3zarvary0c5xw7kw508d6qejxtdg4y5r3zarvary0c5xw7k7grplx",
    ];

    #[test]
    fn the_bip173_and_bip350_strings_decode_and_re_encode() {
        for (list, variant) in [(VALID_BECH32, Variant::Bech32), (VALID_BECH32M, Variant::Bech32m)] {
            for s in list {
                let d = decode(s).unwrap_or_else(|e| panic!("{s}: {e}"));
                assert_eq!(d.variant, variant, "{s}");
                assert_eq!(encode(&d.hrp, &d.data, variant).unwrap(), s.to_ascii_lowercase());
            }
        }
        for s in INVALID {
            assert!(decode(s).is_err(), "{s:?}");
        }
    }

    #[test]
    fn the_segwit_address_vectors() {
        for (address, script) in VALID_ADDRESSES {
            let lower = address.to_ascii_lowercase();
            let hrp = &lower[..2];
            let (version, program) = segwit_decode(hrp, address).unwrap_or_else(|e| panic!("{address}: {e}"));
            let script = hex::decode(script).unwrap();
            let op = if version == 0 { 0 } else { 0x50 + version };
            assert_eq!(script[0], op, "{address}");
            assert_eq!(script[1] as usize, program.len(), "{address}");
            assert_eq!(&script[2..], &program[..], "{address}");
            assert_eq!(segwit_encode(hrp, version, &program).unwrap(), address.to_ascii_lowercase());
        }
        for address in INVALID_ADDRESSES {
            assert!(segwit_decode("bc", address).is_err(), "{address}");
            assert!(segwit_decode("tb", address).is_err(), "{address}");
        }
    }

    #[test]
    fn encoding_refuses_what_decoding_would() {
        assert!(segwit_encode("bc", 17, &[0; 20]).is_err());
        assert!(segwit_encode("bc", 0, &[0; 21]).is_err());
        assert!(segwit_encode("bc", 1, &[0; 41]).is_err());
        assert!(segwit_encode("bc", 1, &[0; 1]).is_err());
        assert!(segwit_encode("bc", 1, &[0; 2]).is_ok());
        assert!(encode("BC", &[0], Variant::Bech32).is_err());
        assert!(encode("bc", &[32], Variant::Bech32).is_err());
        assert!(encode("", &[0], Variant::Bech32).is_err());
    }

    #[test]
    fn bit_conversion_round_trips_and_checks_padding() {
        let bytes: Vec<u8> = (0..=255).collect();
        let five = convert_bits(&bytes, 8, 5, true).unwrap();
        assert_eq!(convert_bits(&five, 5, 8, false).unwrap(), bytes);
    
        assert_eq!(convert_bits(&[0xff; 20], 8, 5, true).unwrap().len(), 32);
        assert!(convert_bits(&[0x1f; 33], 5, 8, false).is_err());
        assert!(convert_bits(&[0x20], 5, 8, true).is_err());
    }
}
