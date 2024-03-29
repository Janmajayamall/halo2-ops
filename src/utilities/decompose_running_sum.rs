//! Decomposes an $n$-bit field element $\alpha$ into $W$ windows, each window
//! being a $K$-bit word, using a running sum $z$.
//! We constrain $K \leq 3$ for this helper.
//!     $$\alpha = k_0 + (2^K) k_1 + (2^{2K}) k_2 + ... + (2^{(W-1)K}) k_{W-1}$$
//!
//! $z_0$ is initialized as $\alpha$. Each successive $z_{i+1}$ is computed as
//!                $$z_{i+1} = (z_{i} - k_i) / (2^K).$$
//! $z_W$ is constrained to be zero.
//! The difference between each interstitial running sum output is constrained
//! to be $K$ bits, i.e.
//!                      `range_check`($k_i$, $2^K$),
//! where
//! ```text
//!   range_check(word, range)
//!     = word * (1 - word) * (2 - word) * ... * ((range - 1) - word)
//! ```
//!
//! Given that the `range_check` constraint will be toggled by a selector, in
//! practice we will have a `selector * range_check(word, range)` expression
//! of degree `range + 1`.
//!
//! This means that $2^K$ has to be at most `degree_bound - 1` in order for
//! the range check constraint to stay within the degree bound.
//!
//! IMPORTANT NOTE: We have copied this from https://github.com/zcash/halo2/tree/main/halo2_gadgets/src/utilities

use ff::PrimeFieldBits;
use halo2_proofs::{
    circuit::{AssignedCell, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Expression, Selector, VirtualCells},
    poly::Rotation,
};

use pasta_curves::arithmetic::FieldExt;
use std::marker::PhantomData;

/// The running sum $[z_0, ..., z_W]$. If created in strict mode, $z_W = 0$.
#[derive(Debug)]
pub struct RunningSum<F: FieldExt + PrimeFieldBits, const WINDOW_NUM_BITS: usize> {
    zs: Vec<AssignedCell<F, F>>,
    num_bits: usize,
    strict: bool,
}

impl<F: FieldExt + PrimeFieldBits, const WINDOW_NUM_BITS: usize> RunningSum<F, WINDOW_NUM_BITS> {
    /// Returns windows derived from the intermediate values of the running sum.
    pub(crate) fn windows(&self) -> Vec<Value<F>> {
        let mut windows = Vec::new();
        // k_i = z_i - (2^K * z_{i+1})
        for i in 0..(self.zs.len() - 1) {
            let z_cur = self.zs[i].value();
            let z_next = self.zs[i + 1].value();
            let window = z_cur
                .zip(z_next)
                .map(|(z_cur, z_next)| *z_cur - *z_next * F::from(1 << WINDOW_NUM_BITS));
            windows.push(window);
        }
        windows
    }

    /// The number of bits represented by the running sum.
    pub(crate) fn num_bits(&self) -> usize {
        self.num_bits
    }

    /// The intermediate values of the running sum.
    pub(crate) fn zs(&self) -> &[AssignedCell<F, F>] {
        &self.zs
    }
}

/// Configuration that provides methods for running sum decomposition.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct RunningSumConfig<F: FieldExt + PrimeFieldBits, const WINDOW_NUM_BITS: usize> {
    q_range_check: Selector,
    z: Column<Advice>,
    _marker: PhantomData<F>,
}

impl<F: FieldExt + PrimeFieldBits, const WINDOW_NUM_BITS: usize>
    RunningSumConfig<F, WINDOW_NUM_BITS>
{
    /// Returns the q_range_check selector of this [`RunningSumConfig`].
    pub(crate) fn q_range_check(&self) -> Selector {
        self.q_range_check
    }

    /// `perm` MUST include the advice column `z`.
    ///
    /// # Side-effects
    ///
    /// `z` will be equality-enabled.
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_range_check: Selector,
        z: Column<Advice>,
    ) -> Self {
        meta.enable_equality(z);

        // It is the caller's responsibility to enforce the range-check using q_range_check.
        // The selector q_range_check will be enabled on every row of the decomposition,
        // but is not tied to a gate or expression within this helper.
        //
        // This is to support different range check methods (e.g. expression, lookup).

        Self {
            q_range_check,
            z,
            _marker: PhantomData,
        }
    }

    /// Expression for a window
    ///    z_i = 2^{K}⋅z_{i + 1} + k_i
    /// => k_i = z_i - 2^{K}⋅z_{i + 1}
    pub(crate) fn window_expr(&self, meta: &mut VirtualCells<'_, F>) -> Expression<F> {
        let z_cur = meta.query_advice(self.z, Rotation::cur());
        let z_next = meta.query_advice(self.z, Rotation::next());
        z_cur - z_next * F::from(1 << WINDOW_NUM_BITS)
    }

    /// Decompose a field element alpha that is witnessed in this helper.
    ///
    /// `strict` = true constrains the final running sum to be zero, i.e.
    /// constrains alpha to be within WINDOW_NUM_BITS * num_windows bits.
    pub fn witness_decompose(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        alpha: Value<F>,
        strict: bool,
        word_num_bits: usize,
        num_windows: usize,
    ) -> Result<RunningSum<F, WINDOW_NUM_BITS>, Error> {
        let z_0 = region.assign_advice(|| "z_0 = alpha", self.z, offset, || alpha)?;
        self.decompose(region, offset, z_0, strict, word_num_bits, num_windows)
    }

    /// Decompose an existing variable alpha that is copied into this helper.
    ///
    /// `strict` = true constrains the final running sum to be zero, i.e.
    /// constrains alpha to be within WINDOW_NUM_BITS * num_windows bits.
    pub fn copy_decompose(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        alpha: AssignedCell<F, F>,
        strict: bool,
        word_num_bits: usize,
        num_windows: usize,
    ) -> Result<RunningSum<F, WINDOW_NUM_BITS>, Error> {
        let z_0 = alpha.copy_advice(|| "copy z_0 = alpha", region, self.z, offset)?;
        self.decompose(region, offset, z_0, strict, word_num_bits, num_windows)
    }

    /// `z_0` must be the cell at `(self.z, offset)` in `region`.
    ///
    /// # Panics
    ///
    /// Panics if there are too many windows for the given word size.
    fn decompose(
        &self,
        region: &mut Region<'_, F>,
        offset: usize,
        z_0: AssignedCell<F, F>,
        strict: bool,
        word_num_bits: usize,
        num_windows: usize,
    ) -> Result<RunningSum<F, WINDOW_NUM_BITS>, Error> {
        // Make sure that we do not have more windows than required for the number
        // of bits in the word. In other words, every window must contain at least
        // one bit of the word (no empty windows).
        //
        // For example, let:
        //      - word_num_bits = 64
        //      - WINDOW_NUM_BITS = 3
        // In this case, the maximum allowed num_windows is 22:
        //                    3 * 22 < 64 + 3
        //
        assert!(WINDOW_NUM_BITS * num_windows < word_num_bits + WINDOW_NUM_BITS);

        // Enable selectors
        for idx in 0..num_windows {
            self.q_range_check.enable(region, offset + idx)?;
        }

        // Decompose base field element into K-bit words.
        let words = z_0
            .value()
            .map(|word| super::decompose_word::<F>(word, word_num_bits, WINDOW_NUM_BITS))
            .transpose_vec(num_windows);

        // Initialize empty vector to store running sum values [z_0, ..., z_W].
        let mut zs: Vec<AssignedCell<F, F>> = vec![z_0.clone()];
        let mut z = z_0;

        // Assign running sum `z_{i+1}` = (z_i - k_i) / (2^K) for i = 0..=n-1.
        // Outside of this helper, z_0 = alpha must have already been loaded into the
        // `z` column at `offset`.
        let two_pow_k_inv = Value::known(F::from(1 << WINDOW_NUM_BITS as u64).invert().unwrap());
        for (i, word) in words.iter().enumerate() {
            // z_next = (z_cur - word) / (2^K)
            let z_next = {
                let z_cur_val = z.value().copied();
                let word = word.map(|word| F::from(word as u64));
                let z_next_val = (z_cur_val - word) * two_pow_k_inv;
                region.assign_advice(
                    || format!("z_{:?}", i + 1),
                    self.z,
                    offset + i + 1,
                    || z_next_val,
                )?
            };

            // Update `z`.
            z = z_next;
            zs.push(z.clone());
        }
        assert_eq!(zs.len(), num_windows + 1);

        if strict {
            // Constrain the final running sum output to be zero.
            region.constrain_constant(zs.last().unwrap().cell(), F::zero())?;
        }

        Ok(RunningSum {
            zs,
            num_bits: word_num_bits,
            strict,
        })
    }
}
