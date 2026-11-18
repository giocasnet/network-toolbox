//! Password generator.
//!
//! Everything happens on this PC, with no network. Randomness comes from the
//! operating system's cryptographic generator (`getrandom`: `ProcessPrng` on Windows).
//!
//! Passwords are drawn **uniformly** among all the strings that satisfy the
//! chosen rules (character types and minimums per type). This is why the
//! entropy shown is exact, log2 of the number of possible passwords, and not the
//! "length × log2(characters)" estimate, which ignores the minimums.

use crate::t;
use crate::tf;
use crate::util::opt_u32;
use serde::{Deserialize, Serialize};

pub const MIN_LEN: u32 = 4;
pub const MAX_LEN: u32 = 64;
pub const DEFAULT_LEN: u32 = 20;
pub const MAX_COUNT: u32 = 10;
pub const DEFAULT_COUNT: u32 = 3;
/// Maximum of the minimum for each character type.
pub const MAX_MIN: u32 = 10;
pub const DEFAULT_MIN: u32 = 1;
pub const DEFAULT_SYMBOLS: &str = "!@#$%^&*()-_=+[]{}|;:,.<>?";
/// Characters that are easily confused on screen or on paper.
pub const AMBIGUOUS: &str = "0Oo1lI|`'\"";

const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const DIGITS: &str = "0123456789";
/// Consonants and vowels of the pronounceable mode (no q, w, x, y).
const CONSONANTS: &str = "bcdfghjklmnprstvz";
const VOWELS: &str = "aeiou";

// ───────────────────────── randomness ─────────────────────────

/// Random generator with a small buffer on top of the system's.
struct Rng {
    buf: [u8; 256],
    pos: usize,
}

impl Rng {
    fn new() -> Self {
        Rng {
            buf: [0; 256],
            pos: 256,
        }
    }

    fn bytes<const N: usize>(&mut self) -> crate::Result<[u8; N]> {
        if self.pos + N > self.buf.len() {
            getrandom::getrandom(&mut self.buf).map_err(|e| {
                tf!(
                    "Generatore casuale del sistema non disponibile: {e}",
                    "System random generator not available: {e}"
                )
            })?;
            self.pos = 0;
        }
        let mut out = [0u8; N];
        out.copy_from_slice(&self.buf[self.pos..self.pos + N]);
        self.pos += N;
        Ok(out)
    }

    /// Uniform integer in `0..n`, without bias (excess values are discarded).
    fn below(&mut self, n: usize) -> crate::Result<usize> {
        debug_assert!(n > 0 && n <= u32::MAX as usize);
        let n = n as u32;
        let limit = u32::MAX - u32::MAX % n;
        loop {
            let x = u32::from_le_bytes(self.bytes::<4>()?);
            if x < limit {
                return Ok((x % n) as usize);
            }
        }
    }

    /// Uniform number in `[0, 1)` with 53 bits of precision.
    fn unit(&mut self) -> crate::Result<f64> {
        let x = u64::from_le_bytes(self.bytes::<8>()?) >> 11;
        Ok(x as f64 / (1u64 << 53) as f64)
    }

    fn pick(&mut self, set: &[u8]) -> crate::Result<u8> {
        Ok(set[self.below(set.len())?])
    }

    /// Fisher-Yates shuffle.
    fn shuffle<T>(&mut self, v: &mut [T]) -> crate::Result<()> {
        for i in (1..v.len()).rev() {
            let j = self.below(i + 1)?;
            v.swap(i, j);
        }
        Ok(())
    }
}

/// Binomial coefficients up to `MAX_LEN`, in floating point.
fn binomials() -> Vec<Vec<f64>> {
    let n = MAX_LEN as usize;
    let mut c = vec![vec![0.0; n + 1]; n + 1];
    for i in 0..=n {
        c[i][0] = 1.0;
        for k in 1..=i {
            c[i][k] = c[i - 1][k - 1] + if k < i { c[i - 1][k] } else { 0.0 };
        }
    }
    c
}

/// Strength based on entropy (the words are codes matched by the UI: not translated).
pub fn strength(bits: f64) -> &'static str {
    if bits < 45.0 {
        "debole"
    } else if bits < 70.0 {
        "media"
    } else if bits < 100.0 {
        "forte"
    } else {
        "estrema"
    }
}

fn round1(x: f64) -> f64 {
    (x * 10.0).round() / 10.0
}

// ───────────────────────── passwords ─────────────────────────

fn yes() -> bool {
    true
}

#[derive(Debug, Clone, Deserialize)]
pub struct PasswordReq {
    #[serde(default = "yes")]
    pub lower: bool,
    #[serde(default = "yes")]
    pub upper: bool,
    #[serde(default = "yes")]
    pub digits: bool,
    #[serde(default = "yes")]
    pub symbols: bool,
    #[serde(default, deserialize_with = "opt_u32")]
    pub min_lower: Option<u32>,
    #[serde(default, deserialize_with = "opt_u32")]
    pub min_upper: Option<u32>,
    #[serde(default, deserialize_with = "opt_u32")]
    pub min_digits: Option<u32>,
    #[serde(default, deserialize_with = "opt_u32")]
    pub min_symbols: Option<u32>,
    /// Symbols to use (empty = `DEFAULT_SYMBOLS`).
    #[serde(default)]
    pub symbol_set: String,
    #[serde(default, deserialize_with = "opt_u32")]
    pub length: Option<u32>,
    #[serde(default, deserialize_with = "opt_u32")]
    pub count: Option<u32>,
    #[serde(default)]
    pub exclude_ambiguous: bool,
    #[serde(default)]
    pub pronounceable: bool,
}

impl Default for PasswordReq {
    fn default() -> Self {
        serde_json::from_str("{}").expect("empty request")
    }
}

/// Entropy and strength of a scheme, without generating passwords (preview).
#[derive(Debug, Clone, Serialize)]
pub struct Estimate {
    pub entropy_bits: f64,
    pub strength: &'static str,
    /// Possible characters in each position (random mode only).
    pub pool: Option<usize>,
    pub length: u32,
    pub pronounceable: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct PasswordResult {
    #[serde(flatten)]
    pub estimate: Estimate,
    pub passwords: Vec<String>,
}

struct Class {
    chars: Vec<u8>,
    min: usize,
}

/// Random mode: `table[i][r]` = number of strings of length `r` made
/// with types `i..` that satisfy the minimums of those types.
struct RandomPlan {
    classes: Vec<Class>,
    len: usize,
    binom: Vec<Vec<f64>>,
    table: Vec<Vec<f64>>,
}

impl RandomPlan {
    fn new(classes: Vec<Class>, len: usize) -> Self {
        let binom = binomials();
        let c = classes.len();
        let mut table = vec![vec![0.0; len + 1]; c + 1];
        table[c][0] = 1.0;
        for i in (0..c).rev() {
            let s = classes[i].chars.len() as f64;
            for r in 0..=len {
                let mut w = 0.0;
                for k in classes[i].min..=r {
                    w += binom[r][k] * s.powi(k as i32) * table[i + 1][r - k];
                }
                table[i][r] = w;
            }
        }
        RandomPlan {
            classes,
            len,
            binom,
            table,
        }
    }

    fn entropy(&self) -> f64 {
        self.table[0][self.len].log2()
    }

    fn generate(&self, rng: &mut Rng) -> crate::Result<String> {
        // 1. how many characters per type, with probability proportional to the number of
        //    passwords that have them; 2. random positions; 3. random character within the type.
        let mut labels = Vec::with_capacity(self.len);
        let mut r = self.len;
        for (i, cl) in self.classes.iter().enumerate() {
            let s = cl.chars.len() as f64;
            let target = rng.unit()? * self.table[i][r];
            let (mut acc, mut pick, mut last) = (0.0, None, cl.min);
            for k in cl.min..=r {
                let w = self.binom[r][k] * s.powi(k as i32) * self.table[i + 1][r - k];
                if w == 0.0 {
                    continue;
                }
                last = k;
                acc += w;
                if target < acc {
                    pick = Some(k);
                    break;
                }
            }
            let k = pick.unwrap_or(last);
            labels.extend(std::iter::repeat_n(i, k));
            r -= k;
        }
        rng.shuffle(&mut labels)?;
        let mut out = String::with_capacity(self.len);
        for i in labels {
            out.push(rng.pick(&self.classes[i].chars)? as char);
        }
        Ok(out)
    }
}

/// Pronounceable mode: letters in consonant/vowel syllables, digits and symbols
/// (exactly `digits` and `symbols`) in random positions.
struct PronPlan {
    len: usize,
    letters: usize,
    /// [consonants, vowels] lowercase and uppercase allowed.
    lower: [Vec<u8>; 2],
    upper: [Vec<u8>; 2],
    min_upper: usize,
    min_lower: usize,
    digit_set: Vec<u8>,
    symbol_set: Vec<u8>,
    digits: usize,
    symbols: usize,
    /// For each start (consonant, vowel): possible completions from every
    /// state (position, uppercase and lowercase already placed, capped at the minimums).
    dp: [Vec<f64>; 2],
}

impl PronPlan {
    fn idx(&self, j: usize, u: usize, l: usize) -> usize {
        (j * (self.min_upper + 1) + u) * (self.min_lower + 1) + l
    }

    fn slot(start: usize, j: usize) -> usize {
        (start + j) % 2
    }

    fn fill_dp(&mut self) {
        let (mu, ml, n) = (self.min_upper, self.min_lower, self.letters);
        for start in 0..2 {
            let mut f = vec![0.0; (n + 1) * (mu + 1) * (ml + 1)];
            let i_end = self.idx(n, mu, ml);
            f[i_end] = 1.0;
            for j in (0..n).rev() {
                let t = Self::slot(start, j);
                let (a, b) = (self.lower[t].len() as f64, self.upper[t].len() as f64);
                for u in 0..=mu {
                    for l in 0..=ml {
                        let lo = f[self.idx(j + 1, u, (l + 1).min(ml))];
                        let up = f[self.idx(j + 1, (u + 1).min(mu), l)];
                        let i = self.idx(j, u, l);
                        f[i] = a * lo + b * up;
                    }
                }
            }
            self.dp[start] = f;
        }
    }

    fn letter_strings(&self) -> [f64; 2] {
        [self.dp[0][0], self.dp[1][0]]
    }

    fn entropy(&self) -> f64 {
        let [a, b] = self.letter_strings();
        let binom = binomials();
        // positions: letters, digits and symbols (multinomial coefficient)
        let arrangements =
            binom[self.len][self.letters] * binom[self.len - self.letters][self.digits];
        (a + b).log2()
            + arrangements.log2()
            + self.digits as f64 * (self.digit_set.len().max(1) as f64).log2()
            + self.symbols as f64 * (self.symbol_set.len().max(1) as f64).log2()
    }

    fn generate(&self, rng: &mut Rng) -> crate::Result<String> {
        let [a, b] = self.letter_strings();
        let start = if rng.unit()? * (a + b) < a { 0 } else { 1 };
        let f = &self.dp[start];
        let (mut u, mut l) = (0, 0);
        let mut letters = Vec::with_capacity(self.letters);
        for j in 0..self.letters {
            let t = Self::slot(start, j);
            let nl = (l + 1).min(self.min_lower);
            let nu = (u + 1).min(self.min_upper);
            let wl = self.lower[t].len() as f64 * f[self.idx(j + 1, u, nl)];
            let wu = self.upper[t].len() as f64 * f[self.idx(j + 1, nu, l)];
            if rng.unit()? * (wl + wu) < wl {
                letters.push(rng.pick(&self.lower[t])?);
                l = nl;
            } else {
                letters.push(rng.pick(&self.upper[t])?);
                u = nu;
            }
        }
        let mut labels: Vec<u8> = std::iter::repeat_n(0u8, self.letters)
            .chain(std::iter::repeat_n(1u8, self.digits))
            .chain(std::iter::repeat_n(2u8, self.symbols))
            .collect();
        rng.shuffle(&mut labels)?;
        let mut it = letters.into_iter();
        let mut out = String::with_capacity(self.len);
        for kind in labels {
            let c = match kind {
                0 => it.next().unwrap_or(b'a'),
                1 => rng.pick(&self.digit_set)?,
                _ => rng.pick(&self.symbol_set)?,
            };
            out.push(c as char);
        }
        Ok(out)
    }
}

enum Plan {
    Random(RandomPlan),
    Pron(PronPlan),
}

fn ranged(v: Option<u32>, def: u32, lo: u32, hi: u32, msg: &str) -> crate::Result<u32> {
    let v = v.unwrap_or(def);
    if (lo..=hi).contains(&v) {
        Ok(v)
    } else {
        Err(msg.to_string())
    }
}

/// Set of characters without duplicates, optionally without the ambiguous ones.
fn chars(src: &str, exclude_ambiguous: bool) -> Vec<u8> {
    let mut v: Vec<u8> = Vec::new();
    for b in src.bytes() {
        if !(exclude_ambiguous && AMBIGUOUS.as_bytes().contains(&b)) && !v.contains(&b) {
            v.push(b);
        }
    }
    v
}

fn symbol_source(set: &str) -> crate::Result<String> {
    if set.trim().is_empty() {
        return Ok(DEFAULT_SYMBOLS.into());
    }
    let mut out = String::new();
    for c in set.chars().filter(|c| !c.is_whitespace()) {
        if !c.is_ascii_punctuation() {
            return Err(tf!(
                "Simboli: ammessi solo segni di punteggiatura ASCII (non «{c}»)",
                "Symbols: only ASCII punctuation marks are allowed (not «{c}»)"
            ));
        }
        out.push(c);
    }
    Ok(out)
}

fn plan(req: &PasswordReq) -> crate::Result<(Plan, u32)> {
    let len = ranged(
        req.length,
        DEFAULT_LEN,
        MIN_LEN,
        MAX_LEN,
        t!(
            "Lunghezza: da 4 a 64 caratteri",
            "Length: 4 to 64 characters"
        ),
    )?;
    let msg = t!("Minimo per tipo: da 0 a 10", "Minimum per type: 0 to 10");
    let mins = [
        ranged(req.min_lower, DEFAULT_MIN, 0, MAX_MIN, msg)? as usize,
        ranged(req.min_upper, DEFAULT_MIN, 0, MAX_MIN, msg)? as usize,
        ranged(req.min_digits, DEFAULT_MIN, 0, MAX_MIN, msg)? as usize,
        ranged(req.min_symbols, DEFAULT_MIN, 0, MAX_MIN, msg)? as usize,
    ];
    let symbols = symbol_source(&req.symbol_set)?;
    let on = [req.lower, req.upper, req.digits, req.symbols];
    if !on.iter().any(|&x| x) {
        return Err(t!(
            "Seleziona almeno un tipo di carattere",
            "Select at least one character type"
        )
        .into());
    }
    let ex = req.exclude_ambiguous;
    let names = [
        t!("minuscole", "lowercase letters"),
        t!("maiuscole", "uppercase letters"),
        t!("numeri", "digits"),
        t!("simboli", "symbols"),
    ];
    let sets = [
        chars(LOWER, ex),
        chars(UPPER, ex),
        chars(DIGITS, ex),
        chars(&symbols, ex),
    ];
    for i in 0..4 {
        if on[i] && sets[i].is_empty() {
            return Err(tf!(
                "Nessun carattere disponibile tra i {}: il set è vuoto{}",
                "No characters available among the {}: the set is empty{}",
                names[i],
                if ex {
                    t!(
                        " dopo l'esclusione dei caratteri ambigui",
                        " after excluding ambiguous characters"
                    )
                } else {
                    ""
                }
            ));
        }
    }
    let len_u = len as usize;

    if !req.pronounceable {
        let classes: Vec<Class> = (0..4)
            .filter(|&i| on[i])
            .map(|i| Class {
                chars: sets[i].clone(),
                min: mins[i],
            })
            .collect();
        let need: usize = classes.iter().map(|c| c.min).sum();
        if need > len_u {
            return Err(tf!(
                "I minimi richiesti ({need} caratteri) superano la lunghezza ({len})",
                "The required minimums ({need} characters) exceed the length ({len})"
            ));
        }
        return Ok((Plan::Random(RandomPlan::new(classes, len_u)), len));
    }

    if !req.lower && !req.upper {
        return Err(t!(
            "La modalità pronunciabile richiede minuscole o maiuscole",
            "Pronounceable mode requires lowercase or uppercase letters"
        )
        .into());
    }
    // digits and symbols: exactly the given minimum, at least 1 if the type is on
    let digits = if req.digits { mins[2].max(1) } else { 0 };
    let nsym = if req.symbols { mins[3].max(1) } else { 0 };
    if digits + nsym + 2 > len_u {
        return Err(t!(
            "In modalità pronunciabile servono almeno 2 lettere: aumenta la lunghezza o riduci numeri e simboli",
            "Pronounceable mode needs at least 2 letters: increase the length or reduce digits and symbols"
        )
        .into());
    }
    let letters = len_u - digits - nsym;
    let min_lower = if req.lower { mins[0] } else { 0 };
    let min_upper = if req.upper { mins[1] } else { 0 };
    if min_lower + min_upper > letters {
        return Err(tf!(
            "I minimi di minuscole e maiuscole ({}) superano le lettere disponibili ({letters})",
            "The minimums of lowercase and uppercase ({}) exceed the available letters ({letters})",
            min_lower + min_upper
        ));
    }
    let case = |src: &str, upper: bool| {
        let s = if upper {
            src.to_ascii_uppercase()
        } else {
            src.to_string()
        };
        chars(&s, ex)
    };
    let mut p = PronPlan {
        len: len_u,
        letters,
        lower: if req.lower {
            [case(CONSONANTS, false), case(VOWELS, false)]
        } else {
            [vec![], vec![]]
        },
        upper: if req.upper {
            [case(CONSONANTS, true), case(VOWELS, true)]
        } else {
            [vec![], vec![]]
        },
        min_upper,
        min_lower,
        digit_set: sets[2].clone(),
        symbol_set: sets[3].clone(),
        digits,
        symbols: nsym,
        dp: [vec![], vec![]],
    };
    p.fill_dp();
    let [a, b] = p.letter_strings();
    if a + b == 0.0 {
        return Err(t!(
            "Impossibile rispettare i minimi con le lettere disponibili",
            "Cannot satisfy the minimums with the available letters"
        )
        .into());
    }
    Ok((Plan::Pron(p), len))
}

fn estimate_of(plan: &Plan, len: u32, pronounceable: bool) -> Estimate {
    let (bits, pool) = match plan {
        Plan::Random(p) => (
            p.entropy(),
            Some(p.classes.iter().map(|c| c.chars.len()).sum()),
        ),
        Plan::Pron(p) => (p.entropy(), None),
    };
    Estimate {
        entropy_bits: round1(bits),
        strength: strength(bits),
        pool,
        length: len,
        pronounceable,
    }
}

/// Entropy of the chosen scheme, for the preview while the options change.
pub fn estimate(req: &PasswordReq) -> crate::Result<Estimate> {
    let (p, len) = plan(req)?;
    Ok(estimate_of(&p, len, req.pronounceable))
}

pub fn generate(req: PasswordReq) -> crate::Result<PasswordResult> {
    let count = ranged(
        req.count,
        DEFAULT_COUNT,
        1,
        MAX_COUNT,
        t!(
            "Quantità: da 1 a 10 password",
            "Quantity: 1 to 10 passwords"
        ),
    )?;
    let (p, len) = plan(&req)?;
    let mut rng = Rng::new();
    let mut passwords = Vec::with_capacity(count as usize);
    for _ in 0..count {
        passwords.push(match &p {
            Plan::Random(p) => p.generate(&mut rng)?,
            Plan::Pron(p) => p.generate(&mut rng)?,
        });
    }
    Ok(PasswordResult {
        estimate: estimate_of(&p, len, req.pronounceable),
        passwords,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(json: &str) -> PasswordReq {
        serde_json::from_str(json).unwrap()
    }

    fn kinds(p: &str) -> [usize; 4] {
        let mut k = [0; 4];
        for c in p.chars() {
            let i = if c.is_ascii_lowercase() {
                0
            } else if c.is_ascii_uppercase() {
                1
            } else if c.is_ascii_digit() {
                2
            } else {
                3
            };
            k[i] += 1;
        }
        k
    }

    #[test]
    fn casuale_uniforme_nei_limiti() {
        let mut r = Rng::new();
        let mut hist = [0usize; 6];
        for _ in 0..60_000 {
            hist[r.below(6).unwrap()] += 1;
        }
        // expected 10,000 per face; 5 standard deviations ≈ 456
        assert!(
            hist.iter().all(|&h| (9_500..=10_500).contains(&h)),
            "{hist:?}"
        );
        for _ in 0..1000 {
            let u = r.unit().unwrap();
            assert!((0.0..1.0).contains(&u));
        }
    }

    #[test]
    fn password_predefinite() {
        let r = generate(PasswordReq::default()).unwrap();
        assert_eq!(r.passwords.len(), 3);
        assert_eq!(r.estimate.pool, Some(88));
        for p in &r.passwords {
            assert_eq!(p.len(), 20);
            assert!(kinds(p).iter().all(|&k| k >= 1), "{p}");
            assert!(p
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || DEFAULT_SYMBOLS.as_bytes().contains(&b)));
        }
        // just under 20 × log2(88) = 129.2: the minimums exclude some strings
        assert!(r.estimate.entropy_bits > 128.0 && r.estimate.entropy_bits < 129.2);
        assert_eq!(r.estimate.strength, "estrema");
    }

    #[test]
    fn minimi_rispettati() {
        let q = req(
            r#"{"length":"12","count":"10","min_lower":"0","min_upper":"3","min_digits":"4","min_symbols":"5"}"#,
        );
        for _ in 0..50 {
            for p in generate(q.clone()).unwrap().passwords {
                let k = kinds(&p);
                assert_eq!(p.len(), 12);
                assert!(k[1] >= 3 && k[2] >= 4 && k[3] >= 5, "{p}");
            }
        }
    }

    #[test]
    fn tipi_disattivati_e_ambigui() {
        let q = req(
            r#"{"upper":false,"symbols":false,"exclude_ambiguous":true,"length":"64","count":"10"}"#,
        );
        for p in generate(q).unwrap().passwords {
            assert!(
                p.bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit()),
                "{p}"
            );
            assert!(!p.bytes().any(|b| AMBIGUOUS.as_bytes().contains(&b)), "{p}");
        }
        let q = req(
            r#"{"lower":false,"upper":false,"digits":false,"symbol_set":"! @ #","length":"30"}"#,
        );
        for p in generate(q).unwrap().passwords {
            assert!(p.bytes().all(|b| b"!@#".contains(&b)), "{p}");
        }
    }

    #[test]
    fn entropia_esatta() {
        // a single type, no minimum: 10 × log2(26)
        let e = estimate(&req(
            r#"{"upper":false,"digits":false,"symbols":false,"min_lower":"0","length":"10"}"#,
        ))
        .unwrap();
        assert_eq!(e.entropy_bits, round1(10.0 * 26f64.log2()));
        // lowercase and digits, length 4, at least one per type: 36^4 - 26^4 - 10^4
        let e = estimate(&req(r#"{"upper":false,"symbols":false,"length":"4"}"#)).unwrap();
        let n = 36f64.powi(4) - 26f64.powi(4) - 10f64.powi(4);
        assert_eq!(e.entropy_bits, round1(n.log2()));
        // four types with minimum 1, length 20: inclusion-exclusion
        let s = [26.0, 26.0, 10.0, 26.0];
        let mut n = 0.0;
        for mask in 0u32..16 {
            let excluded: f64 = (0..4).filter(|i| mask & (1 << i) != 0).map(|i| s[i]).sum();
            let sign = if mask.count_ones() % 2 == 0 {
                1.0
            } else {
                -1.0
            };
            n += sign * (88.0 - excluded).powi(20);
        }
        let e = estimate(&PasswordReq::default()).unwrap();
        assert_eq!(e.entropy_bits, round1(n.log2()));
    }

    #[test]
    fn distribuzione_uniforme_con_minimi() {
        // digits and symbols "!@" (12 characters), length 4, at least one per type:
        // 12^4 - 10^4 - 2^4 possible passwords
        let q = req(r#"{"lower":false,"upper":false,"symbol_set":"!@","length":"4","count":"1"}"#);
        let e = estimate(&q).unwrap();
        let n = 12f64.powi(4) - 10f64.powi(4) - 2f64.powi(4);
        assert_eq!(e.entropy_bits, round1(n.log2()));
        // uniform draw: the share of passwords starting with a symbol must
        // be that of the valid strings with a symbol at the front
        let mut hits = 0;
        let runs = 20_000;
        let plan = match plan(&q).unwrap().0 {
            Plan::Random(p) => p,
            Plan::Pron(_) => unreachable!(),
        };
        let mut rng = Rng::new();
        for _ in 0..runs {
            if plan.generate(&mut rng).unwrap().starts_with(['!', '@']) {
                hits += 1;
            }
        }
        // symbol at the front: 2 × (12^3 - 2^3), because the rest must contain a digit
        let expect = 2.0 * (12f64.powi(3) - 2f64.powi(3)) / n * runs as f64;
        assert!(
            (hits as f64 - expect).abs() < 5.0 * expect.sqrt(),
            "{hits} vs {expect}"
        );
    }

    #[test]
    fn pronunciabile() {
        let q = req(
            r#"{"pronounceable":true,"length":"16","count":"10","min_digits":"2","min_symbols":"0"}"#,
        );
        let r = generate(q).unwrap();
        assert!(r.estimate.pool.is_none());
        for p in r.passwords {
            let k = kinds(&p);
            assert_eq!(p.len(), 16);
            assert_eq!(k[2], 2, "{p}");
            assert_eq!(k[3], 1, "{p}");
            assert!(k[0] >= 1 && k[1] >= 1, "{p}");
            let letters: Vec<char> = p.chars().filter(|c| c.is_ascii_alphabetic()).collect();
            let vowel = |c: &char| VOWELS.contains(c.to_ascii_lowercase());
            for w in letters.windows(2) {
                assert_ne!(vowel(&w[0]), vowel(&w[1]), "{p}");
            }
        }
        // lowercase only, 4 letters: CVCV + VCVC = 2 · 17·5·17·5
        let q = req(
            r#"{"pronounceable":true,"upper":false,"digits":false,"symbols":false,"length":"4"}"#,
        );
        let e = estimate(&q).unwrap();
        let n = 17f64 * 5.0 * 17.0 * 5.0 * 2.0;
        assert_eq!(e.entropy_bits, round1(n.log2()));
        // lowercase and uppercase with at least one per type, 4 letters: for each start
        // (34·10)^2 - 2·(17·5)^2
        let q = req(r#"{"pronounceable":true,"digits":false,"symbols":false,"length":"4"}"#);
        let n = 2.0 * (340f64.powi(2) - 2.0 * 85f64.powi(2));
        assert_eq!(estimate(&q).unwrap().entropy_bits, round1(n.log2()));
        // with ambiguous characters excluded: no l, o, I, O
        let q =
            req(r#"{"pronounceable":true,"exclude_ambiguous":true,"length":"40","count":"10"}"#);
        for p in generate(q).unwrap().passwords {
            assert!(!p.bytes().any(|b| AMBIGUOUS.as_bytes().contains(&b)), "{p}");
        }
    }

    #[test]
    fn errori_in_inglese() {
        let _g = crate::i18n::scoped(crate::i18n::Lang::En);
        let err = |j: &str| generate(req(j)).unwrap_err();
        assert_eq!(err(r#"{"length":"3"}"#), "Length: 4 to 64 characters");
        assert_eq!(err(r#"{"count":"0"}"#), "Quantity: 1 to 10 passwords");
        assert_eq!(err(r#"{"min_digits":"11"}"#), "Minimum per type: 0 to 10");
        assert_eq!(
            err(r#"{"lower":false,"upper":false,"digits":false,"symbols":false}"#),
            "Select at least one character type"
        );
        let e = err(r#"{"length":"8","min_digits":"5","min_symbols":"5"}"#);
        assert!(
            e.contains("exceed the length") && !e.contains("superano"),
            "{e}"
        );
        let e = err(
            r#"{"lower":false,"upper":false,"digits":false,"symbol_set":"|`'\"","exclude_ambiguous":true}"#,
        );
        assert!(
            e.contains("symbols") && e.contains("excluding ambiguous"),
            "{e}"
        );
        assert!(
            err(r#"{"pronounceable":true,"lower":false,"upper":false}"#).contains("Pronounceable")
        );
        // strength codes stay the same in every language
        assert_eq!(strength(10.0), "debole");
    }

    #[test]
    fn errori_in_italiano() {
        let err = |j: &str| generate(req(j)).unwrap_err();
        assert_eq!(err(r#"{"length":"3"}"#), "Lunghezza: da 4 a 64 caratteri");
        assert_eq!(err(r#"{"length":"65"}"#), "Lunghezza: da 4 a 64 caratteri");
        assert_eq!(err(r#"{"count":"0"}"#), "Quantità: da 1 a 10 password");
        assert_eq!(err(r#"{"count":"11"}"#), "Quantità: da 1 a 10 password");
        assert_eq!(err(r#"{"min_digits":"11"}"#), "Minimo per tipo: da 0 a 10");
        assert!(err(r#"{"length":"8","min_digits":"5","min_symbols":"5"}"#)
            .contains("superano la lunghezza"));
        assert_eq!(
            err(r#"{"lower":false,"upper":false,"digits":false,"symbols":false}"#),
            "Seleziona almeno un tipo di carattere"
        );
        assert!(err(r#"{"symbol_set":"!a"}"#).contains("«a»"));
        assert!(err(r#"{"lower":false,"upper":false,"digits":false,"symbol_set":"|`'\"","exclude_ambiguous":true}"#)
            .contains("simboli"));
        assert!(
            err(r#"{"pronounceable":true,"lower":false,"upper":false}"#).contains("pronunciabile")
        );
        assert!(
            err(r#"{"pronounceable":true,"length":"6","min_digits":"3","min_symbols":"2"}"#)
                .contains("almeno 2 lettere")
        );
        assert!(serde_json::from_str::<PasswordReq>(r#"{"length":"x"}"#).is_err());
    }
}
