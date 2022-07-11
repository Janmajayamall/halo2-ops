use ff::PrimeFieldBits;
mod decompose_running_sum;

/// Decompose a word `alpha` into `window_num_bits` bits (little-endian)
/// For a window size of `w`, this returns [k_0, ..., k_n] where each `k_i`
/// is a `w`-bit value, and `scalar = k_0 + k_1 * w + k_n * w^n`.
pub fn decompose_word<F: PrimeFieldBits>(
    word: &F,
    word_num_bits: usize,
    window_num_bits: usize,
) -> Vec<u8> {
    // Pad bits to multiple of window_num_bits
    let padding = (window_num_bits - (word_num_bits % window_num_bits)) % window_num_bits;
    let bits: Vec<bool> = word
        .to_le_bits()
        .into_iter()
        .take(word_num_bits)
        .chain(std::iter::repeat(false).take(padding))
        .collect();
    assert_eq!(bits.len(), word_num_bits + padding);

    bits.chunks_exact(window_num_bits)
        .map(|chunk| chunk.iter().rev().fold(0, |acc, b| (acc << 1) + (*b as u8)))
        .collect()
}
