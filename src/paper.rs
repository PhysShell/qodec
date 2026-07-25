//! `paper` — faithful baseline reproduction of the dictionary encoder in
//! arXiv:2604.13066 ("Lossless Prompt Compression via Dictionary-Encoding and
//! In-Context Learning", de Campos, Lee, Kissos, Paritosh). The related-work
//! rung of the comparison ladder: qodec's miners must beat *this*, measured,
//! or the extra machinery is not earning its keep.
//!
//! What is copied from the paper, deliberately including its known weaknesses
//! (whitespace-only segmentation, greedy longest-first, per-pattern-only
//! acceptance):
//! * whitespace segmentation into word units;
//! * n-gram levels from `lmax` down to 2, longest first;
//! * within a level, candidates ranked by frequency (descending);
//! * overlap prevention via used-position marking, frequency recomputed on
//!   the surviving non-overlapping occurrences;
//! * no nested aliases — a shorter pattern never crosses an already-committed
//!   replacement;
//! * auto-incrementing `<M#>` meta-tokens, counter advancing on acceptance;
//! * batch-local dictionary — every artifact carries its own;
//! * per-pattern acceptance is the paper's Equation 1 and nothing else:
//!   `(1+f)·ntoken(M) + ntoken(S) < f·ntoken(S)`.
//!
//! Divergences, each forced by this lab's stricter ground rules:
//! * **Byte-exact grouping.** The paper joins word units and scores line-level
//!   reconstruction; here two occurrences are the same pattern only if their
//!   exact byte slices match (interior whitespace included), so decode is
//!   byte-exact — a strictly finer grouping, never a looser one.
//! * **Serialization.** The paper never specifies its dictionary format; here
//!   entries are `%q1` legend lines `<M1>=value` with `\n`/`\r`/`\\` escaped.
//! * **Alias collision.** The paper does not address input that already
//!   contains `<M<digits>>`; here that input fails closed to a `raw`
//!   container instead of risking a wrong reconstruction.
//! * **Meter.** `ntoken(·)` is the lab meter (o200k by default) — the paper
//!   used Claude's tokenizer, which is not public; same proxy argument as the
//!   rest of the lab.
//!
//! Deliberately **not** added: a whole-artifact acceptance gate. The paper
//! accepts per pattern only, so its artifact may lose net tokens once the real
//! serialized envelope is paid — that gap is precisely what the baseline
//! exists to measure. The one exception is zero accepted entries, where the
//! honest artifact is `raw` (nothing was compressed). `squeeze`/`mosaic`
//! never route through this codec; it is a measuring stick, not a stage.

use std::collections::HashMap;

use anyhow::{bail, Result};

use crate::container::{self, Container};
use crate::meter::TokenMeter;

/// The paper evaluates `L_max` from 3 to 20 without recommending a default;
/// 20 is the top of their tested range, so the baseline is never handicapped
/// by a shorter window than the paper ever used.
pub const DEFAULT_LMAX: usize = 20;
/// Minimum occurrence count. Equation 1 already rejects every `f = 1`
/// pattern, so 2 is the weakest threshold that changes nothing else.
pub const DEFAULT_FMIN: usize = 2;

pub fn encode(text: &str, meter: &dyn TokenMeter) -> String {
    encode_with(text, meter, DEFAULT_LMAX, DEFAULT_FMIN)
}

pub fn encode_with(text: &str, meter: &dyn TokenMeter, lmax: usize, fmin: usize) -> String {
    // Fail closed on alias collision: input already speaking `<M#>` cannot be
    // told apart from our replacements at decode time.
    if text.is_empty() || contains_meta_token(text) {
        return container::raw(text);
    }

    let words = word_spans(text);
    // (alias, phrase) in acceptance order — the dictionary.
    let mut entries: Vec<(String, String)> = Vec::new();
    // Committed byte spans, disjoint by construction.
    let mut used: Vec<(usize, usize)> = Vec::new();
    // (start, end, entry index) for the final single-pass substitution.
    let mut replacements: Vec<(usize, usize, usize)> = Vec::new();

    for len in (2..=lmax.max(2)).rev() {
        if words.len() < len {
            continue;
        }
        // Group this level's occurrences by exact byte slice. First-seen
        // order is kept so the frequency sort below is deterministic.
        let mut groups: HashMap<&str, Vec<(usize, usize)>> = HashMap::new();
        let mut order: Vec<&str> = Vec::new();
        for i in 0..=(words.len() - len) {
            let (Some(&(start, _)), Some(&(_, end))) = (words.get(i), words.get(i + len - 1))
            else {
                continue;
            };
            if overlaps_any(&used, start, end) {
                continue;
            }
            let Some(slice) = text.get(start..end) else {
                continue;
            };
            match groups.entry(slice) {
                std::collections::hash_map::Entry::Occupied(mut o) => {
                    o.get_mut().push((start, end))
                }
                std::collections::hash_map::Entry::Vacant(v) => {
                    v.insert(vec![(start, end)]);
                    order.push(slice);
                }
            }
        }
        // Frequency descending; the stable sort keeps first-seen order on ties.
        order.sort_by_key(|slice| {
            std::cmp::Reverse(groups.get(slice).map_or(0, std::vec::Vec::len))
        });

        for slice in order {
            let Some(occs) = groups.get(slice) else {
                continue;
            };
            // Greedy left-to-right non-overlap, re-checked against spans
            // committed earlier in this same level; frequency is recomputed
            // on the survivors, as in the paper's Algorithm 2.
            let mut chosen: Vec<(usize, usize)> = Vec::new();
            for &(start, end) in occs {
                if overlaps_any(&used, start, end) {
                    continue;
                }
                if chosen.last().is_some_and(|&(_, prev_end)| start < prev_end) {
                    continue;
                }
                chosen.push((start, end));
            }
            let f = chosen.len();
            if f < fmin {
                continue;
            }
            let alias = format!("<M{}>", entries.len() + 1);
            let m_tok = meter.count(&alias) as i64;
            let s_tok = meter.count(slice) as i64;
            let f_i = f as i64;
            // Equation 1: (1+f)·ntoken(M) + ntoken(S) < f·ntoken(S).
            if (1 + f_i) * m_tok + s_tok >= f_i * s_tok {
                continue;
            }
            for &(start, end) in &chosen {
                used.push((start, end));
                replacements.push((start, end, entries.len()));
            }
            entries.push((alias, slice.to_string()));
        }
    }

    if entries.is_empty() {
        return container::raw(text);
    }

    replacements.sort_by_key(|&(start, _, _)| start);
    let mut body = String::new();
    let mut pos = 0usize;
    for &(start, end, idx) in &replacements {
        if let Some(gap) = text.get(pos..start) {
            body.push_str(gap);
        }
        if let Some((alias, _)) = entries.get(idx) {
            body.push_str(alias);
        }
        pos = end;
    }
    if let Some(rest) = text.get(pos..) {
        body.push_str(rest);
    }

    let legend = entries
        .iter()
        .map(|(alias, phrase)| format!("{alias}={}", escape(phrase)))
        .collect();
    container::emit(&Container {
        codec: "paper".to_string(),
        params: vec![
            ("n".to_string(), entries.len().to_string()),
            ("lmax".to_string(), lmax.to_string()),
            ("fmin".to_string(), fmin.to_string()),
        ],
        legend,
        body,
    })
}

pub fn decode(c: &Container) -> Result<String> {
    let mut dict: HashMap<String, String> = HashMap::new();
    for line in &c.legend {
        let Some((alias, value)) = line.split_once('=') else {
            bail!("paper: malformed legend line {line:?}");
        };
        if meta_token_at(alias.as_bytes(), 0) != Some(alias.len()) {
            bail!("paper: legend key {alias:?} is not a <M#> meta-token");
        }
        dict.insert(alias.to_string(), unescape(value)?);
    }

    // Single left-to-right pass — dictionary values contain no meta-tokens
    // (the encoder fails closed on collision), so expansion never recurses.
    let bytes = c.body.as_bytes();
    let mut out = String::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if let Some(end) = meta_token_at(bytes, i) {
            let Some(alias) = c.body.get(i..end) else {
                bail!("paper: meta-token spans a non-UTF-8 boundary");
            };
            let Some(value) = dict.get(alias) else {
                bail!("paper: alias {alias} missing from dictionary — refusing lossy decode");
            };
            out.push_str(value);
            i = end;
        } else {
            let Some(ch) = c.body.get(i..).and_then(|rest| rest.chars().next()) else {
                break;
            };
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    Ok(out)
}

/// Byte offsets of maximal non-whitespace runs — the paper's "non-empty word
/// units". Whitespace between them is preserved by slicing the source.
fn word_spans(text: &str) -> Vec<(usize, usize)> {
    let mut spans = Vec::new();
    let mut start: Option<usize> = None;
    for (i, ch) in text.char_indices() {
        if ch.is_whitespace() {
            if let Some(s) = start.take() {
                spans.push((s, i));
            }
        } else if start.is_none() {
            start = Some(i);
        }
    }
    if let Some(s) = start {
        spans.push((s, text.len()));
    }
    spans
}

/// If a `<M<digits>>` token starts at byte `at`, its exclusive end offset.
fn meta_token_at(bytes: &[u8], at: usize) -> Option<usize> {
    if bytes.get(at) != Some(&b'<') || bytes.get(at.checked_add(1)?) != Some(&b'M') {
        return None;
    }
    let mut i = at.checked_add(2)?;
    let mut digits = 0usize;
    while bytes.get(i).is_some_and(u8::is_ascii_digit) {
        digits += 1;
        i = i.checked_add(1)?;
    }
    (digits > 0 && bytes.get(i) == Some(&b'>')).then_some(i.checked_add(1)?)
}

fn contains_meta_token(text: &str) -> bool {
    let bytes = text.as_bytes();
    (0..bytes.len()).any(|i| meta_token_at(bytes, i).is_some())
}

fn overlaps_any(used: &[(usize, usize)], start: usize, end: usize) -> bool {
    used.iter().any(|&(us, ue)| start < ue && us < end)
}

/// Legend lines are line-framed and CRLF-normalized by the container parser,
/// so a phrase's `\n`, `\r` and `\\` must travel escaped.
fn escape(phrase: &str) -> String {
    let mut out = String::with_capacity(phrase.len());
    for ch in phrase.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            other => out.push(other),
        }
    }
    out
}

fn unescape(value: &str) -> Result<String> {
    let mut out = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            Some('\\') => out.push('\\'),
            other => bail!("paper: bad legend escape \\{other:?}"),
        }
    }
    Ok(out)
}
