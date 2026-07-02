// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Xpress "plain LZ77" compression, as specified by [MS-XCA] sections 2.3
//! (Plain LZ77 Compression) and 2.4 (Plain LZ77 Decompression).
//!
//! This is the same variant that `RtlCompressBuffer` /
//! `RtlDecompressBufferEx` use with `COMPRESSION_FORMAT_XPRESS`, and that
//! Hyper-V's `VmSavedStateDumpProvider.dll` uses to decompress the RAM blocks
//! of a `.vmrs` saved-state file. Only the *compressor* is needed to produce
//! WinDbg-compatible dumps; a matching [`decompress`] is provided for
//! round-trip testing.
//!
//! # Format summary
//!
//! The stream is a sequence of tokens preceded by 32-bit little-endian flag
//! words. Each flag word describes up to 32 tokens, MSB first: a `0` bit is a
//! literal byte, a `1` bit is a back-reference (match). Matches encode a
//! 13-bit offset (window is 8192 bytes) and a variable-length count with a
//! minimum match of 3 bytes.
//!
//! [MS-XCA]: https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-xca

#![forbid(unsafe_code)]

/// Minimum match length. Matches shorter than this are emitted as literals.
const MIN_MATCH: usize = 3;

/// Maximum representable match length. The count is ultimately bounded by the
/// 16-bit extension field: `length = uint16 + 3`.
const MAX_MATCH: usize = u16::MAX as usize + MIN_MATCH;

/// Maximum back-reference distance. The offset is stored in 13 bits as
/// `offset - 1`, so distances range from 1 to 8192.
const MAX_OFFSET: usize = 8192;

/// Number of entries in the match-finder hash table.
const HASH_BITS: u32 = 15;
const HASH_SIZE: usize = 1 << HASH_BITS;

/// Maximum number of candidates examined per position by the match finder.
/// Bounds the worst-case compression time on highly repetitive input.
const MAX_CHAIN: usize = 32;

/// An error returned while decompressing a malformed Xpress stream.
#[derive(Debug, thiserror::Error)]
pub enum DecompressError {
    /// The input ended before the requested output was produced.
    #[error("unexpected end of compressed input")]
    UnexpectedEof,
    /// A match referenced an offset before the start of the output.
    #[error("match offset points before start of output")]
    InvalidOffset,
    /// The stream produced more output than the caller expected.
    #[error("decompressed output exceeded expected size")]
    OutputOverflow,
    /// A length-extension field encoded a value smaller than its own bias.
    #[error("corrupted match-length encoding")]
    CorruptedData,
}

/// Compresses `input` using the Xpress plain LZ77 algorithm.
///
/// The returned buffer decompresses back to `input` via [`decompress`] (with
/// `output_size == input.len()`), and is accepted by Windows'
/// `COMPRESSION_FORMAT_XPRESS` decompressor.
pub fn compress(input: &[u8]) -> Vec<u8> {
    let mut enc = Encoder::new(input.len());

    // Hash-chain match finder. `head[h]` is the most recent position whose
    // 3-byte prefix hashed to `h`; `prev[i]` chains to the previous such
    // position. Positions are 1-based so that 0 means "none".
    let mut head = vec![0u32; HASH_SIZE];
    let mut prev = vec![0u32; input.len()];

    let mut i = 0;
    while i < input.len() {
        let (len, offset) = if i + MIN_MATCH <= input.len() {
            find_match(input, i, &head, &prev)
        } else {
            (0, 0)
        };

        if len >= MIN_MATCH {
            enc.push_match(len, offset);
            // Insert every covered position into the hash chains so future
            // matches can reference them.
            let end = i + len;
            while i < end {
                if i + MIN_MATCH <= input.len() {
                    insert(input, i, &mut head, &mut prev);
                }
                i += 1;
            }
        } else {
            enc.push_literal(input[i]);
            if i + MIN_MATCH <= input.len() {
                insert(input, i, &mut head, &mut prev);
            }
            i += 1;
        }
    }

    enc.finish()
}

/// Computes the hash-table index for the 3 bytes starting at `input[pos]`.
fn hash(input: &[u8], pos: usize) -> usize {
    let b = [input[pos], input[pos + 1], input[pos + 2]];
    let v = u32::from(b[0]) | (u32::from(b[1]) << 8) | (u32::from(b[2]) << 16);
    // Fibonacci hashing into HASH_BITS bits.
    ((v.wrapping_mul(2654435761)) >> (32 - HASH_BITS)) as usize
}

/// Inserts `pos` into the hash chains keyed by its 3-byte prefix.
fn insert(input: &[u8], pos: usize, head: &mut [u32], prev: &mut [u32]) {
    let h = hash(input, pos);
    prev[pos] = head[h];
    // Store as 1-based so that 0 is the "empty" sentinel.
    head[h] = pos as u32 + 1;
}

/// Finds the longest match for the data at `input[pos]`, searching the hash
/// chain within the 8192-byte window. Returns `(length, offset)`, or `(0, 0)`
/// if no match of at least [`MIN_MATCH`] bytes is found.
fn find_match(input: &[u8], pos: usize, head: &[u32], prev: &[u32]) -> (usize, usize) {
    let max_len = (input.len() - pos).min(MAX_MATCH);
    if max_len < MIN_MATCH {
        return (0, 0);
    }
    let window_start = pos.saturating_sub(MAX_OFFSET);

    let mut best_len = 0;
    let mut best_offset = 0;
    let mut chain = MAX_CHAIN;
    let mut cand = head[hash(input, pos)];
    while cand != 0 && chain != 0 {
        let candidate = cand as usize - 1;
        if candidate < window_start {
            break;
        }
        // Quick reject: only extend candidates that can beat the current best.
        if best_len == 0 || input[candidate + best_len] == input[pos + best_len] {
            let mut len = 0;
            while len < max_len && input[candidate + len] == input[pos + len] {
                len += 1;
            }
            if len > best_len {
                best_len = len;
                best_offset = pos - candidate;
                if len == max_len {
                    break;
                }
            }
        }
        cand = prev[candidate];
        chain -= 1;
    }

    if best_len >= MIN_MATCH {
        (best_len, best_offset)
    } else {
        (0, 0)
    }
}

/// Emits the token stream and interleaved flag words.
struct Encoder {
    out: Vec<u8>,
    /// Accumulated flag bits for the current group, filled MSB-first.
    flags: u32,
    /// Number of tokens accumulated into `flags` so far (0..=32).
    flag_count: u32,
    /// Index in `out` of the reserved 4-byte slot for the current flag word.
    flags_pos: usize,
    /// Index in `out` of a byte whose high nibble is still available for a
    /// match-length half-byte, or `None`.
    last_nibble_pos: Option<usize>,
}

impl Encoder {
    fn new(input_len: usize) -> Self {
        let mut out = Vec::with_capacity(input_len / 2 + 16);
        let flags_pos = reserve_flags(&mut out);
        Self {
            out,
            flags: 0,
            flag_count: 0,
            flags_pos,
            last_nibble_pos: None,
        }
    }

    /// Records a flag bit (`0` = literal, `1` = match), flushing and reserving
    /// a new flag word every 32 tokens.
    fn push_bit(&mut self, bit: u32) {
        if self.flag_count == 32 {
            self.out[self.flags_pos..self.flags_pos + 4].copy_from_slice(&self.flags.to_le_bytes());
            self.flags = 0;
            self.flag_count = 0;
            self.flags_pos = reserve_flags(&mut self.out);
        }
        self.flags = (self.flags << 1) | bit;
        self.flag_count += 1;
    }

    fn push_literal(&mut self, byte: u8) {
        self.push_bit(0);
        self.out.push(byte);
    }

    fn push_match(&mut self, len: usize, offset: usize) {
        debug_assert!((MIN_MATCH..=MAX_MATCH).contains(&len));
        debug_assert!((1..=MAX_OFFSET).contains(&offset));
        self.push_bit(1);

        let e = len - MIN_MATCH;
        let low = e.min(7) as u16;
        let match_bytes = (((offset - 1) as u16) << 3) | low;
        self.out.extend_from_slice(&match_bytes.to_le_bytes());

        if e < 7 {
            return;
        }

        // Length >= 10: the low 3 bits held 7; emit the remainder as a
        // half-byte, then optionally a byte and a 16-bit word.
        let rem = e - 7;
        if rem < 15 {
            self.push_nibble(rem as u8);
        } else {
            self.push_nibble(15);
            let rem2 = rem - 15;
            if rem2 < 255 {
                self.out.push(rem2 as u8);
            } else {
                self.out.push(255);
                self.out.extend_from_slice(&(e as u16).to_le_bytes());
            }
        }
    }

    /// Emits a match-length half-byte, packing two nibbles per byte. The low
    /// nibble is written first; the next nibble fills the high half of the
    /// same byte.
    fn push_nibble(&mut self, value: u8) {
        match self.last_nibble_pos.take() {
            None => {
                self.out.push(value & 0x0F);
                self.last_nibble_pos = Some(self.out.len() - 1);
            }
            Some(pos) => {
                self.out[pos] |= (value & 0x0F) << 4;
            }
        }
    }

    /// Finalizes the stream, appending a terminating match flag and writing
    /// out the pending flag word.
    fn finish(mut self) -> Vec<u8> {
        // A match flag with no following bytes marks end-of-stream: the
        // decompressor sees a match indicator with the input exhausted and
        // stops. This makes the stream self-terminating in addition to being
        // bounded by the known output size.
        self.push_bit(1);
        // Left-align the remaining flag bits into the high end of the word.
        self.flags <<= 32 - self.flag_count;
        self.out[self.flags_pos..self.flags_pos + 4].copy_from_slice(&self.flags.to_le_bytes());
        self.out
    }
}

/// Reserves 4 zero bytes for a flag word and returns their start index.
fn reserve_flags(out: &mut Vec<u8>) -> usize {
    let pos = out.len();
    out.extend_from_slice(&[0; 4]);
    pos
}

/// Decompresses an Xpress plain LZ77 stream produced by [`compress`],
/// producing exactly `output_size` bytes.
///
/// This mirrors the [MS-XCA] plain LZ77 decompression algorithm, bounded by
/// the known output size (as Windows' decompressor is, given the destination
/// buffer length).
pub fn decompress(input: &[u8], output_size: usize) -> Result<Vec<u8>, DecompressError> {
    let mut out = Vec::with_capacity(output_size);
    let mut ip = 0usize;
    let mut flags = 0u32;
    let mut flag_count = 0u32;
    // Position of a byte whose high nibble holds a pending match-length
    // half-byte, or 0 for "none". Position 0 is always inside the first flag
    // word, so it never names a real nibble byte.
    let mut last_nibble_pos = 0usize;

    let read_u16 = |input: &[u8], ip: usize| -> Result<u16, DecompressError> {
        input
            .get(ip..ip + 2)
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .ok_or(DecompressError::UnexpectedEof)
    };

    while out.len() < output_size {
        if flag_count == 0 {
            let word = input
                .get(ip..ip + 4)
                .ok_or(DecompressError::UnexpectedEof)?;
            flags = u32::from_le_bytes([word[0], word[1], word[2], word[3]]);
            ip += 4;
            flag_count = 32;
        }
        let is_match = flags & (1 << 31) != 0;
        flags <<= 1;
        flag_count -= 1;

        if !is_match {
            let &byte = input.get(ip).ok_or(DecompressError::UnexpectedEof)?;
            ip += 1;
            out.push(byte);
            continue;
        }

        // End-of-stream: a match indicator with the input exhausted.
        if ip == input.len() {
            break;
        }

        let match_bytes = read_u16(input, ip)?;
        ip += 2;
        let offset = (match_bytes >> 3) as usize + 1;
        let mut len = (match_bytes & 7) as usize;
        if len == 7 {
            if last_nibble_pos == 0 {
                len = (*input.get(ip).ok_or(DecompressError::UnexpectedEof)? & 0x0F) as usize;
                last_nibble_pos = ip;
                ip += 1;
            } else {
                len = (input[last_nibble_pos] >> 4) as usize;
                last_nibble_pos = 0;
            }
            if len == 15 {
                len = *input.get(ip).ok_or(DecompressError::UnexpectedEof)? as usize;
                ip += 1;
                if len == 255 {
                    len = read_u16(input, ip)? as usize;
                    ip += 2;
                    // Guard against malformed input: this crate's compressor
                    // never emits a value below the bias, but `decompress` is
                    // public and must not panic on arbitrary input.
                    len = len
                        .checked_sub(15 + 7)
                        .ok_or(DecompressError::CorruptedData)?;
                }
                len += 15;
            }
            len += 7;
        }
        len += MIN_MATCH;

        if offset > out.len() {
            return Err(DecompressError::InvalidOffset);
        }
        if out.len() + len > output_size {
            return Err(DecompressError::OutputOverflow);
        }
        let start = out.len() - offset;
        for k in 0..len {
            out.push(out[start + k]);
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn round_trip(data: &[u8]) {
        let compressed = compress(data);
        let restored = decompress(&compressed, data.len()).unwrap();
        assert_eq!(restored, data, "round trip mismatch (len {})", data.len());
    }

    #[test]
    fn empty() {
        round_trip(&[]);
    }

    #[test]
    fn single_byte() {
        round_trip(&[0x42]);
    }

    #[test]
    fn no_repeats() {
        let data: Vec<u8> = (0u8..=255).collect();
        round_trip(&data);
    }

    #[test]
    fn all_zeros_small() {
        round_trip(&[0u8; 100]);
    }

    #[test]
    fn all_zeros_large() {
        // Exercises long matches, the 16-bit length extension, and match
        // splitting beyond MAX_MATCH.
        round_trip(&vec![0u8; 1 << 20]);
    }

    #[test]
    fn zeros_compress_well() {
        let compressed = compress(&vec![0u8; 1 << 20]);
        assert!(
            compressed.len() < 1024,
            "1 MiB of zeros compressed to {} bytes",
            compressed.len()
        );
    }

    #[test]
    fn repeated_pattern() {
        let mut data = Vec::new();
        for i in 0..10_000u32 {
            data.extend_from_slice(&i.to_le_bytes());
        }
        // Overwrite the tail with a long run to force the nibble/byte length
        // extension paths at various boundaries.
        data.extend(std::iter::repeat_n(0xAB, 40));
        round_trip(&data);
    }

    #[test]
    fn match_length_boundaries() {
        // Runs whose length exercises each length-encoding branch: inline
        // 3-bit, nibble, byte extension, and 16-bit extension.
        for run in [3, 9, 10, 24, 25, 279, 280, 5000, 70_000] {
            let mut data = vec![0x5A];
            data.extend(std::iter::repeat_n(0x5A, run));
            round_trip(&data);
        }
    }

    #[test]
    fn offset_boundaries() {
        // A match at exactly the maximum window distance must still decode.
        let mut data = vec![0u8; MAX_OFFSET];
        data[0] = 1;
        data[1] = 2;
        data[2] = 3;
        data.push(1);
        data.push(2);
        data.push(3);
        round_trip(&data);
    }

    #[test]
    fn pseudo_random() {
        // A simple LCG gives deterministic, hard-to-compress input.
        let mut state = 0x1234_5678u32;
        let mut data = vec![0u8; 64 * 1024];
        for b in &mut data {
            state = state.wrapping_mul(1_103_515_245).wrapping_add(12_345);
            *b = (state >> 16) as u8;
        }
        round_trip(&data);
    }

    #[test]
    fn mixed_content() {
        let mut data = Vec::new();
        data.extend_from_slice(b"The quick brown fox jumps over the lazy dog. ");
        data.extend(std::iter::repeat_n(0u8, 4096));
        data.extend_from_slice(b"The quick brown fox jumps over the lazy dog. ");
        data.extend(std::iter::repeat_n(0xFFu8, 300));
        round_trip(&data);
    }

    #[test]
    fn high_nibble_packing() {
        // Two consecutive matches that each use the 7 + half-byte length
        // encoding force the second length nibble to be packed into the high
        // half of the first nibble byte. This is the exact path that must
        // record the nibble byte's position correctly.
        let p: Vec<u8> = (0..12).collect();
        let q: Vec<u8> = (100..112).collect();
        let mut data = Vec::new();
        data.extend_from_slice(&p);
        data.extend_from_slice(&p); // match of length 12 -> low nibble
        data.extend_from_slice(&q);
        data.extend_from_slice(&q); // match of length 12 -> high nibble
        round_trip(&data);

        // Three nibble matches: low, high, then a fresh low nibble byte.
        let r: Vec<u8> = (200..214).collect();
        data.extend_from_slice(&r);
        data.extend_from_slice(&r);
        round_trip(&data);
    }

    #[test]
    fn token_count_multiple_of_32() {
        // Strictly increasing bytes never form a 3-byte match, so each byte is
        // a literal token. A length that is a multiple of 32 finalizes exactly
        // on a flag-word boundary, exercising the end-of-stream flush without a
        // shift-by-32 overflow.
        for len in [32usize, 64, 96] {
            let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
            round_trip(&data);
        }
    }

    #[test]
    fn rejects_corrupt_length() {
        // A match token claiming the 16-bit length extension with a value below
        // the bias must be rejected rather than panicking.
        // Flags: one match token (high bit set), rest zero.
        let mut stream = 0x8000_0000u32.to_le_bytes().to_vec();
        // match_bytes: offset field 0 (=> offset 1), low 3 bits = 7.
        stream.extend_from_slice(&7u16.to_le_bytes());
        stream.push(0x0F); // nibble = 15 -> take byte extension
        stream.push(255); // byte = 255 -> take u16 extension
        stream.extend_from_slice(&1u16.to_le_bytes()); // u16 = 1 (< bias 22)
        assert!(matches!(
            decompress(&stream, 64),
            Err(DecompressError::CorruptedData)
        ));
    }
}
