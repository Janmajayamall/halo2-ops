use halo2_proofs::{
    arithmetic::FieldExt,
    plonk::{Advice, Column, ConstraintSystem, Constraints, Expression, Selector},
};
use pasta_curves::pallas;

use crate::canonicity;

/// The Pallas base field modulus is $p = 2^{254} + \mathsf{t_p}$.
/// <https://github.com/zcash/pasta>
pub(crate) const T_P: u128 = 45560315531419706090280762371685220353;

#[derive(Debug, Clone)]
struct Config {
    q_check: Selector,
    canonicity_config: canonicity::Config,
    col_x: Column<Advice>,
    col_a: Column<Advice>,
    col_b: Column<Advice>,
    col_c: Column<Advice>,
}

impl Config {
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        col_x: Column<Advice>,
        col_a: Column<Advice>,
        col_b: Column<Advice>,
        col_c: Column<Advice>,
    ) -> Self {
        let q_check = meta.selector();

        let two_pow_126 = Expression::Constant(pallas::Base::from_u128(1 << 63).square());
        let two_pow_254 = Expression::Constant(pallas::Base::from_u128(1 << 127).square());
        let t_p = Expression::Constant(pallas::Base::from_u128(T_P));
        let canonicity_config =
            canonicity::Config::configure(meta, col_a, col_b, col_c, two_pow_254, two_pow_126, t_p);

        let config = Self {
            q_check,
            canonicity_config,
            col_x,
            col_a,
            col_b,
            col_c,
        };

        config
    }
}
