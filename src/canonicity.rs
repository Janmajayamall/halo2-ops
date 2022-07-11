use core::iter;
use halo2_proofs::{
    plonk::{Advice, Column, ConstraintSystem, Constraints, Expression, Selector, VirtualCells},
    poly::Rotation,
};
use pasta_curves::pallas;

/// |   A_1   | A_2 |    A_3     | q_canonicity |
/// -------------------------------------------------------------------
/// | x       | a   |    b       |         1         |
/// |         | a_prime |            |         0         |
///
/// x = a + b * 2^250 + c * 2^254
///
/// a is 126 bit value
/// b is 118 bit value
/// c is 1 bit value
/// a_prime = a + (2^126 - tp)
///
/// Main Constraints
/// (1) x = a + b * 2^126 + c * 2^254
/// (2) c * b = 0
/// (3) c * a_prime = 0
/// (4) a_prime = a + 2^126 - t_p
#[derive(Debug, Clone)]
pub struct Config {
    q_canon: Selector,
    col_a: Column<Advice>,
    col_b: Column<Advice>,
    col_c: Column<Advice>,
}

impl Config {
    #[allow(clippy::too_many_arguments)]
    pub fn configure(
        meta: &mut ConstraintSystem<pallas::Base>,
        col_a: Column<Advice>,
        col_b: Column<Advice>,
        col_c: Column<Advice>,
        two_pow_254: Expression<pallas::Base>,
        two_pow_126: Expression<pallas::Base>,
        t_p: Expression<pallas::Base>,
    ) -> Self {
        let q_canon = meta.selector();

        let config = Self {
            q_canon,
            col_a,
            col_b,
            col_c,
        };

        meta.create_gate("Canonicity check", |meta| {
            let q_canon = meta.query_selector(config.q_canon);

            let a = meta.query_advice(config.col_a, Rotation::cur());
            let a_prime = meta.query_advice(config.col_a, Rotation::next());
            let b = meta.query_advice(config.col_b, Rotation::cur());
            let c = meta.query_advice(config.col_c, Rotation::cur());

            let check_x = a.clone() + (b.clone() * two_pow_126.clone()) + (c.clone() * two_pow_254);
            let canon_checks = iter::empty()
                .chain(Some(("c * b = 0", c.clone() * b)))
                .chain(Some(("c * a_prime = 0", c * a_prime)));
            let a_prime_check = a + two_pow_126 - t_p;

            Constraints::with_selector(
                q_canon,
                iter::empty()
                    .chain(Some(("check_x", check_x)))
                    .chain(Some(("a_prime_check", a_prime_check)))
                    .chain(canon_checks),
            )
        });

        config
    }
}
