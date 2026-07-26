//! Token meters — the only ground truth in this lab.
//!
//! Every codec decision is *measured* against a real tokenizer, never
//! estimated from bytes or characters. Claude's tokenizer is not public, so
//! `o200k` (GPT-4o/o1 family BPE, bundled offline by tiktoken-rs) serves as
//! the default proxy; the relative ordering of codec outcomes is what
//! transfers across BPE tokenizers, and the trait keeps the door open for an
//! API-backed Anthropic meter later.

use anyhow::{bail, Result};

pub trait TokenMeter {
    fn name(&self) -> &str;
    /// Stable identity for drift stamps (`cost` datasets/models). For bundled
    /// meters the name is the identity — "o200k" always means the same BPE.
    /// File-backed meters must override this to bind the stamp to the
    /// tokenizer's *contents*, not its path: a `tokenizer.json` swapped in
    /// place after harvesting would otherwise pass the fail-closed check
    /// while counting with a different tokenizer (Codex review on PR #9).
    fn identity(&self) -> String {
        self.name().to_string()
    }
    fn count(&self, text: &str) -> usize;
    /// `true` once a `count` has failed. A fail-closed meter (the HF tokenizer)
    /// never returns a guessed count on error — it marks itself poisoned and the
    /// CLI aborts with no token result, so a run can never silently proceed on
    /// fabricated numbers. The BPE/char meters cannot fail and stay `false`.
    fn poisoned(&self) -> bool {
        false
    }
}

pub struct Bpe {
    name: &'static str,
    bpe: tiktoken_rs::CoreBPE,
}

impl Bpe {
    pub fn o200k() -> Result<Self> {
        Ok(Self {
            name: "o200k",
            bpe: tiktoken_rs::o200k_base()?,
        })
    }

    pub fn cl100k() -> Result<Self> {
        Ok(Self {
            name: "cl100k",
            bpe: tiktoken_rs::cl100k_base()?,
        })
    }
}

impl TokenMeter for Bpe {
    fn name(&self) -> &str {
        self.name
    }

    fn count(&self, text: &str) -> usize {
        self.bpe.encode_ordinary(text).len()
    }
}

/// Char-count heuristic (~3.5 chars/token). Only for fast property tests;
/// bench and encode default to a real BPE.
pub struct Approx;

impl TokenMeter for Approx {
    fn name(&self) -> &str {
        "approx"
    }

    fn count(&self, text: &str) -> usize {
        // ceil(chars * 2 / 7) == ceil(chars / 3.5)
        let chars = text.chars().count();
        (chars * 2).div_ceil(7)
    }
}

/// A meter backed by a real model's `tokenizer.json` (the Hugging Face
/// `tokenizers` format — GLM, Qwen, Llama, …). This is what makes Level 2
/// honest: aliases and codec acceptance are chosen under the tokenizer the
/// served model actually reads, not an o200k proxy. In-process (the Rust
/// `tokenizers` crate), so a count costs no subprocess.
pub struct HfMeter {
    name: String,
    /// `hf:<path>#<fnv1a64 of file bytes>` — see [`TokenMeter::identity`].
    identity: String,
    tokenizer: tokenizers::Tokenizer,
    /// Interior mutability: `count` takes `&self` but must record a failure.
    /// Single-threaded CLI use, so a `Cell` is enough (no `Sync` needed).
    poisoned: std::cell::Cell<bool>,
}

impl HfMeter {
    /// Load from a `tokenizer.json` path. The meter name is `hf:<path>` so
    /// reports and run records identify which tokenizer produced the numbers.
    /// A probe encode runs at load so a structurally-valid-but-unusable
    /// tokenizer fails here rather than mid-run.
    pub fn from_file(path: &str) -> Result<Self> {
        let bytes =
            std::fs::read(path).map_err(|e| anyhow::anyhow!("reading tokenizer {path}: {e}"))?;
        let tokenizer = tokenizers::Tokenizer::from_file(path)
            .map_err(|e| anyhow::anyhow!("loading tokenizer {path}: {e}"))?;
        tokenizer
            .encode("qodec meter probe", false)
            .map_err(|e| anyhow::anyhow!("tokenizer {path} cannot encode a probe string: {e}"))?;
        Ok(Self {
            name: format!("hf:{path}"),
            identity: format!("hf:{path}#{:016x}", fnv1a64(&bytes)),
            tokenizer,
            poisoned: std::cell::Cell::new(false),
        })
    }
}

/// FNV-1a 64 over the tokenizer file bytes. An *accident* detector for drift
/// stamps — catches a `tokenizer.json` silently replaced under the same path
/// — not a security boundary; no crypto dependency is worth that here.
fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut h = 0xcbf2_9ce4_8422_2325u64;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

impl TokenMeter for HfMeter {
    fn name(&self) -> &str {
        &self.name
    }

    fn identity(&self) -> String {
        self.identity.clone()
    }

    fn count(&self, text: &str) -> usize {
        // `add_special_tokens = false`: count the content's own tokens, not the
        // chat-template wrapping the server adds — that is what the codec
        // optimizes and what raw-vs-encoded must be compared on.
        //
        // Fail closed: if the tokenizer cannot encode this input, do NOT guess a
        // char count (that would silently corrupt every downstream measurement
        // and the L2 verdict). Poison the meter and return 0; the CLI checks
        // `poisoned()` and aborts with no token result.
        match self.tokenizer.encode(text, false) {
            Ok(enc) => enc.len(),
            Err(_) => {
                self.poisoned.set(true);
                0
            }
        }
    }

    fn poisoned(&self) -> bool {
        self.poisoned.get()
    }
}

pub fn by_name(name: &str) -> Result<Box<dyn TokenMeter>> {
    if let Some(path) = name.strip_prefix("hf:") {
        return Ok(Box::new(HfMeter::from_file(path)?));
    }
    match name {
        "o200k" => Ok(Box::new(Bpe::o200k()?)),
        "cl100k" => Ok(Box::new(Bpe::cl100k()?)),
        "approx" => Ok(Box::new(Approx)),
        other => bail!(
            "unknown meter {other:?} (expected o200k | cl100k | approx | hf:<tokenizer.json>)"
        ),
    }
}
