// mod bit_check;
// mod canonicity;
// mod range_check;
// mod utilities;

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use ecc::{integer::Range, EccConfig, GeneralEccChip};
    use ecdsa::ecdsa::{AssignedEcdsaSig, AssignedPublicKey, EcdsaChip};
    use ff::PrimeField;
    use halo2::{
        arithmetic::{CurveAffine, Field, FieldExt},
        circuit::{SimpleFloorPlanner, Value},
        dev::MockProver,
        halo2curves::{
            group::{Curve, Group},
            pasta::Fp as PastaFp,
            secp256k1::Secp256k1Affine,
        },
        plonk::Circuit,
    };
    use integer::IntegerInstructions;
    use maingate::{
        MainGate, MainGateConfig, RangeChip, RangeConfig, RangeInstructions, RegionCtx,
    };
    use num_bigint::BigUint;
    use num_traits::Num;
    use rand_core::OsRng;

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
    fn test_ecdsa() {
        // from group's base field to scalar field
        fn mod_n<C: CurveAffine>(x: C::Base) -> C::Scalar {
            // convert to bigint
            let x = BigUint::from_bytes_le(x.to_repr().as_ref());

            // calculate mod scalar modulus
            let modulus =
                BigUint::from_str_radix(&<C::Scalar as FieldExt>::MODULUS[2..], 16).unwrap();
            let x = x % modulus;

            <C::Scalar as PrimeField>::from_str_vartime(&x.to_str_radix(10)[..]).unwrap()
        }

        fn run<C: CurveAffine, N: FieldExt>() {
            let g = C::generator();
            // keypair
            let sk = <C as CurveAffine>::ScalarExt::random(OsRng);
            let pk = (g * sk).to_affine();

            // random msg_hash
            let msg_hash = <C as CurveAffine>::ScalarExt::random(OsRng);

            // Generate sig

            // k
            let k = <C as CurveAffine>::ScalarExt::random(OsRng);
            let k_inv = k.invert().unwrap();

            // r
            let rpoint = (g * k).to_affine().coordinates().unwrap();
            let x = rpoint.x();
            let r = mod_n::<C>(*x);

            // s
            let s = k_inv * (msg_hash + (r * sk));

            {
                // Ensuring signature is valid
                let s_inv = s.invert().unwrap();
                let u_1 = msg_hash * s_inv;
                let u_2 = r * s_inv;
                let r_point = ((g * u_1) + (pk * u_2)).to_affine().coordinates().unwrap();
                let x_candidate = r_point.x();
                let r_candidate = mod_n::<C>(*x_candidate);
                assert_eq!(r, r_candidate);
            }

            // prove valid signature
            let k = 20;
            let aux_generator = C::CurveExt::random(OsRng).to_affine();
            let ecdsa_circuit = EcdsaCircuit::<C, N> {
                public_key: Value::known(pk),
                msg_hash: Value::known(msg_hash),
                signature: Value::known((r, s)),

                aux_generator,
                window_size: 2,
                _marker: PhantomData,
            };

            let public_inputs = vec![vec![]];
            let prover = match MockProver::run(k, &ecdsa_circuit, public_inputs) {
                Ok(prover) => prover,
                Err(e) => panic!("{:#?}", e),
            };
            assert_eq!(prover.verify(), Ok(()));
        }

        run::<Secp256k1Affine, PastaFp>();
    }
}
