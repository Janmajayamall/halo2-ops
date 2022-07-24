// mod bit_check;
// mod canonicity;
// mod range_check;
// mod utilities;

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use ecc::{integer::Range, EccConfig, GeneralEccChip};
    use ecdsa::ecdsa::{AssignedEcdsaSig, AssignedPublicKey, EcdsaChip};
    use halo2::{
        arithmetic::{CurveAffine, FieldExt},
        circuit::{SimpleFloorPlanner, Value},
        plonk::Circuit,
    };
    use integer::IntegerInstructions;
    use maingate::{
        MainGate, MainGateConfig, RangeChip, RangeConfig, RangeInstructions, RegionCtx,
    };
    const BIT_LEN_LIMB: usize = 68;
    const NUMBER_OF_LIMBS: usize = 4;

    #[derive(Clone, Debug)]
    struct EcdsaConfig {
        maingate_config: MainGateConfig,
        rangecheck_config: RangeConfig,
    }

    #[derive(Clone, Debug, Default)]
    struct EcdsaCircuit<E: CurveAffine, N: FieldExt> {
        public_key: Value<E>,
        signature: Value<(E::Scalar, E::Scalar)>,
        msg_hash: Value<E::Scalar>,

        aux_generator: E,
        window_size: usize,
        _marker: PhantomData<N>,
    }

    impl<E: CurveAffine, N: FieldExt> Circuit<N> for EcdsaCircuit<E, N> {
        type Config = EcdsaConfig;
        type FloorPlanner = SimpleFloorPlanner;

        fn configure(meta: &mut ecc::halo2::plonk::ConstraintSystem<N>) -> Self::Config {
            let (rns_base, rns_scalar) =
                GeneralEccChip::<E, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::rns();
            let maingate_config = MainGate::<N>::configure(meta);
            let mut overflow_bit_lens: Vec<usize> = vec![];
            overflow_bit_lens.extend(rns_base.overflow_lengths());
            overflow_bit_lens.extend(rns_scalar.overflow_lengths());
            let composition_bit_lens = vec![BIT_LEN_LIMB / NUMBER_OF_LIMBS];

            let rangecheck_config = RangeChip::<N>::configure(
                meta,
                &maingate_config,
                composition_bit_lens,
                overflow_bit_lens,
            );

            EcdsaConfig {
                maingate_config,
                rangecheck_config,
            }
        }

        fn without_witnesses(&self) -> Self {
            Self::default()
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl halo2::circuit::Layouter<N>,
        ) -> Result<(), halo2::plonk::Error> {
            let ecc_config = EccConfig::new(
                config.rangecheck_config.clone(),
                config.maingate_config.clone(),
            );
            let mut ecc_chip =
                GeneralEccChip::<E, N, NUMBER_OF_LIMBS, BIT_LEN_LIMB>::new(ecc_config);
            let scalar_chip = ecc_chip.scalar_field_chip();

            layouter.assign_region(
                || "assign aux values",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);

                    ecc_chip.assign_aux_generator(ctx, Value::known(self.aux_generator))?;
                    ecc_chip.assign_aux(ctx, self.window_size, 1)?;
                    Ok(())
                },
            )?;

            let ecdsa_chip = EcdsaChip::new(ecc_chip.clone());

            layouter.assign_region(
                || "region 0",
                |mut region| {
                    let offset = &mut 0;
                    let ctx = &mut RegionCtx::new(&mut region, offset);

                    let r = self.signature.map(|signature| signature.0);
                    let s = self.signature.map(|signature| signature.1);
                    let integer_r = ecc_chip.new_unassigned_scalar(r);
                    let integer_s = ecc_chip.new_unassigned_scalar(s);
                    let msg_hash = ecc_chip.new_unassigned_scalar(self.msg_hash);

                    let r_assigned =
                        scalar_chip.assign_integer(ctx, integer_r, Range::Remainder)?;
                    let s_assigned =
                        scalar_chip.assign_integer(ctx, integer_s, Range::Remainder)?;
                    let sig = AssignedEcdsaSig {
                        r: r_assigned,
                        s: s_assigned,
                    };

                    let pk_in_circuit = ecc_chip.assign_point(ctx, self.public_key)?;
                    let pk_assigned = AssignedPublicKey {
                        point: pk_in_circuit,
                    };
                    let msg_hash = scalar_chip.assign_integer(ctx, msg_hash, Range::Remainder)?;
                    ecdsa_chip.verify(ctx, &sig, &pk_assigned, &msg_hash)
                },
            )?;

            // configure range check
            let range_chip = RangeChip::<N>::new(config.rangecheck_config.clone());
            range_chip.load_composition_tables(&mut layouter)?;
            range_chip.load_overflow_tables(&mut layouter)?;

            Ok(())
        }
    }

    #[test]
    fn it_works() {
        let result = 2 + 2;
        assert_eq!(result, 4);
    }
}
