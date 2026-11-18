//! BER encoding (subset used by SNMP): TLV, integers, OIDs, strings.

pub const INTEGER: u8 = 0x02;
pub const OCTET_STRING: u8 = 0x04;
pub const NULL: u8 = 0x05;
pub const OID: u8 = 0x06;
pub const SEQUENCE: u8 = 0x30;

pub fn len_bytes(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else {
        let b = (n as u64).to_be_bytes();
        let skip = b.iter().take_while(|x| **x == 0).count();
        let mut v = vec![0x80 | (8 - skip) as u8];
        v.extend_from_slice(&b[skip..]);
        v
    }
}

pub fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut v = vec![tag];
    v.extend(len_bytes(content.len()));
    v.extend_from_slice(content);
    v
}

pub fn int(n: i64) -> Vec<u8> {
    let b = n.to_be_bytes();
    let mut start = 0;
    while start < 7 {
        let (cur, next) = (b[start], b[start + 1]);
        if (cur == 0x00 && next & 0x80 == 0) || (cur == 0xff && next & 0x80 != 0) {
            start += 1;
        } else {
            break;
        }
    }
    tlv(INTEGER, &b[start..])
}

pub fn octets(b: &[u8]) -> Vec<u8> {
    tlv(OCTET_STRING, b)
}

pub fn null() -> Vec<u8> {
    vec![NULL, 0]
}

pub fn oid(arcs: &[u32]) -> Vec<u8> {
    let mut c = Vec::new();
    let (a, b) = (
        arcs.first().copied().unwrap_or(0),
        arcs.get(1).copied().unwrap_or(0),
    );
    let mut push = |mut v: u64| {
        let mut tmp = vec![(v & 0x7f) as u8];
        v >>= 7;
        while v > 0 {
            tmp.push(0x80 | (v & 0x7f) as u8);
            v >>= 7;
        }
        tmp.reverse();
        c.extend(tmp);
    };
    push(a as u64 * 40 + b as u64);
    for x in arcs.iter().skip(2) {
        push(*x as u64);
    }
    tlv(OID, &c)
}

pub fn seq(parts: &[Vec<u8>]) -> Vec<u8> {
    tlv(SEQUENCE, &parts.concat())
}

/// BER reader. `base` is the absolute position of the buffer in the original message.
#[derive(Clone)]
pub struct Reader<'a> {
    pub buf: &'a [u8],
    pub pos: usize,
    pub base: usize,
}

pub type BerResult<T> = std::result::Result<T, String>;

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader {
            buf,
            pos: 0,
            base: 0,
        }
    }

    pub fn at_end(&self) -> bool {
        self.pos >= self.buf.len()
    }

    /// Reads a TLV: (tag, content, absolute position of the content).
    pub fn tlv(&mut self) -> BerResult<(u8, &'a [u8], usize)> {
        let err = || {
            crate::t!(
                "Messaggio SNMP non valido (BER troncato)",
                "Invalid SNMP message (truncated BER)"
            )
            .to_string()
        };
        let tag = *self.buf.get(self.pos).ok_or_else(err)?;
        let first = *self.buf.get(self.pos + 1).ok_or_else(err)?;
        let mut p = self.pos + 2;
        let len = if first & 0x80 == 0 {
            first as usize
        } else {
            let n = (first & 0x7f) as usize;
            if n == 0 || n > 4 {
                return Err(err());
            }
            let mut l = 0usize;
            for _ in 0..n {
                l = (l << 8) | *self.buf.get(p).ok_or_else(err)? as usize;
                p += 1;
            }
            l
        };
        let content = self.buf.get(p..p + len).ok_or_else(err)?;
        self.pos = p + len;
        Ok((tag, content, self.base + p))
    }

    pub fn expect(&mut self, tag: u8) -> BerResult<(&'a [u8], usize)> {
        let (t, c, at) = self.tlv()?;
        if t != tag {
            return Err(crate::tf!(
                "Messaggio SNMP non valido (atteso tag 0x{tag:02x}, trovato 0x{t:02x})",
                "Invalid SNMP message (expected tag 0x{tag:02x}, found 0x{t:02x})"
            ));
        }
        Ok((c, at))
    }

    /// Reader over the content of a constructed TLV (SEQUENCE, PDU).
    pub fn enter(&mut self, tag: u8) -> BerResult<Reader<'a>> {
        let (c, at) = self.expect(tag)?;
        Ok(Reader {
            buf: c,
            pos: 0,
            base: at,
        })
    }

    pub fn int(&mut self) -> BerResult<i64> {
        let (c, _) = self.expect(INTEGER)?;
        Ok(decode_int(c))
    }

    pub fn octets(&mut self) -> BerResult<&'a [u8]> {
        Ok(self.expect(OCTET_STRING)?.0)
    }
}

pub fn decode_int(c: &[u8]) -> i64 {
    if c.is_empty() {
        return 0;
    }
    let mut v: i64 = if c[0] & 0x80 != 0 { -1 } else { 0 };
    for b in c.iter().take(8) {
        v = (v << 8) | *b as i64;
    }
    v
}

pub fn decode_uint(c: &[u8]) -> u64 {
    c.iter().take(9).fold(0u64, |a, b| (a << 8) | *b as u64)
}

pub fn decode_oid(c: &[u8]) -> Vec<u32> {
    let mut arcs = Vec::new();
    let mut v: u64 = 0;
    for (i, b) in c.iter().enumerate() {
        v = (v << 7) | (b & 0x7f) as u64;
        if b & 0x80 == 0 {
            if arcs.is_empty() {
                let (x, y) = if v < 40 {
                    (0, v)
                } else if v < 80 {
                    (1, v - 40)
                } else {
                    (2, v - 80)
                };
                arcs.push(x as u32);
                arcs.push(y as u32);
            } else {
                arcs.push(v as u32);
            }
            v = 0;
        } else if i == c.len() - 1 {
            break;
        }
    }
    arcs
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interi() {
        assert_eq!(int(0), vec![2, 1, 0]);
        assert_eq!(int(127), vec![2, 1, 0x7f]);
        assert_eq!(int(128), vec![2, 2, 0, 0x80]);
        assert_eq!(int(-1), vec![2, 1, 0xff]);
        assert_eq!(int(-129), vec![2, 2, 0xff, 0x7f]);
        assert_eq!(int(65507), vec![2, 3, 0x00, 0xff, 0xe3]);
        for n in [
            0i64,
            1,
            -1,
            127,
            128,
            -128,
            -129,
            2_147_483_647,
            -2_147_483_648,
        ] {
            assert_eq!(decode_int(&int(n)[2..]), n);
        }
    }

    #[test]
    fn oid_e_lunghezze() {
        let o = [1u32, 3, 6, 1, 4, 1, 9999, 101, 4, 1, 3, 0];
        let enc = oid(&o);
        assert_eq!(&enc[..4], &[6, 12, 0x2b, 6]);
        assert_eq!(decode_oid(&enc[2..]), o.to_vec());
        assert_eq!(len_bytes(200), vec![0x81, 200]);
        assert_eq!(len_bytes(1000), vec![0x82, 0x03, 0xe8]);
        let big = tlv(OCTET_STRING, &vec![7u8; 1000]);
        let mut r = Reader::new(&big);
        assert_eq!(r.octets().unwrap().len(), 1000);
    }
}
