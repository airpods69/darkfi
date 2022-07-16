use std::marker::PhantomData;

use group::ff::PrimeFieldBits;
use halo2_proofs::{
    arithmetic::FieldExt,
    circuit::{AssignedCell, Chip, Layouter, Region, Value},
    plonk::{Advice, Column, ConstraintSystem, Error, Selector, TableColumn},
    poly::Rotation,
};

#[derive(Clone, Debug)]
pub struct RangeCheckConfig {
    pub z: Column<Advice>,
    pub s_rc: Selector,
    pub k_values_table: TableColumn,
}

#[derive(Clone, Debug)]
pub struct RangeCheckChip<F: FieldExt + PrimeFieldBits, const WINDOW_SIZE: usize> {
    config: RangeCheckConfig,
    _marker: PhantomData<F>,
}

impl<F: FieldExt + PrimeFieldBits, const WINDOW_SIZE: usize> Chip<F>
    for RangeCheckChip<F, WINDOW_SIZE>
{
    type Config = RangeCheckConfig;
    type Loaded = ();

    fn config(&self) -> &Self::Config {
        &self.config
    }

    fn loaded(&self) -> &Self::Loaded {
        &()
    }
}

impl<F: FieldExt + PrimeFieldBits, const WINDOW_SIZE: usize> RangeCheckChip<F, WINDOW_SIZE> {
    pub fn construct(config: RangeCheckConfig) -> Self {
        Self { config, _marker: PhantomData }
    }

    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        k_values_table: TableColumn,
    ) -> RangeCheckConfig {
        let z = meta.advice_column();
        meta.enable_equality(z);

        let s_rc = meta.complex_selector();

        let config = RangeCheckConfig { z, s_rc, k_values_table };

        meta.lookup(|meta| {
            let s_rc = meta.query_selector(config.s_rc);
            let z_curr = meta.query_advice(config.z, Rotation::cur());
            let z_next = meta.query_advice(config.z, Rotation::next());

            //    z_next = (z_curr - k_i) / 2^K
            // => k_i = z_curr - (z_next * 2^K)
            vec![(s_rc * (z_curr - z_next * F::from(1 << WINDOW_SIZE)), config.k_values_table)]
        });

        config
    }

    /// `k_values_table` should be reused across different chips
    /// which is why we don't limit it to a specific instance.
    pub fn load_k_table(
        layouter: &mut impl Layouter<F>,
        k_values_table: TableColumn,
    ) -> Result<(), Error> {
        layouter.assign_table(
            || format!("{} window table", WINDOW_SIZE),
            |mut table| {
                for index in 0..(1 << WINDOW_SIZE) {
                    table.assign_cell(
                        || "table",
                        k_values_table,
                        index,
                        || Value::known(F::from(index as u64)),
                    )?;
                }
                Ok(())
            },
        )
    }

    pub fn witness_range_check(
        &self,
        layouter: &mut impl Layouter<F>,
        value: Value<F>,
        offset: usize,
        num_of_bits: usize,
        num_of_windows: usize,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "witness range check",
            |mut region: Region<'_, F>| {
                let z_0 = region.assign_advice(|| "z_0", self.config.z, offset, || value)?;
                self.decompose(region, z_0, offset, num_of_bits, num_of_windows)?;
                Ok(())
            },
        )
    }

    pub fn copy_range_check(
        &self,
        layouter: &mut impl Layouter<F>,
        value: AssignedCell<F, F>,
        offset: usize,
        num_of_bits: usize,
        num_of_windows: usize,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "copy range check",
            |mut region: Region<'_, F>| {
                let z_0 = value.copy_advice(|| "z_0", &mut region, self.config.z, offset)?;
                self.decompose(region, z_0, offset, num_of_bits, num_of_windows)?;
                Ok(())
            },
        )
    }

    pub fn decompose(
        &self,
        mut region: Region<'_, F>,
        z_0: AssignedCell<F, F>,
        offset: usize,
        num_of_bits: usize,
        num_of_windows: usize,
    ) -> Result<(), Error> {
        assert!(WINDOW_SIZE * num_of_windows < num_of_bits + WINDOW_SIZE);

        // enable selectors
        for index in 0..num_of_windows {
            self.config.s_rc.enable(&mut region, index + offset)?;
        }

        let mut z_values: Vec<AssignedCell<F, F>> = vec![z_0.clone()];
        let mut z = z_0.clone();
        let decomposed_chunks = z_0
            .value()
            .map(|val| decompose_value::<F, WINDOW_SIZE>(val, num_of_bits))
            .transpose_vec(num_of_windows);

        let two_pow_k_inverse = Value::known(F::from(1 << WINDOW_SIZE as u64).invert().unwrap());
        for (i, chunk) in decomposed_chunks.iter().enumerate() {
            let z_next = {
                let z_curr = z.value().copied();
                let chunk_value =
                    chunk.map(|c| F::from(c.iter().rev().fold(0, |acc, c| (acc << 1) + *c as u64)));
                // z_next = (z_curr - k_i) / 2^K
                let z_next = (z_curr - chunk_value) * two_pow_k_inverse;
                region.assign_advice(
                    || format!("z_{}", i + offset + 1),
                    self.config.z,
                    i + offset,
                    || z_next,
                )?
            };
            z_values.push(z_next.clone());
            z = z_next.clone();
        }

        assert!(z_values.len() == num_of_windows + 1);

        region.constrain_constant(z_values.last().unwrap().cell(), F::zero())?;

        Ok(())
    }
}

/// ### Reference  
pub fn decompose_value<F: FieldExt + PrimeFieldBits, const WINDOW_SIZE: usize>(
    value: &F,
    num_of_bits: usize,
) -> Vec<[bool; WINDOW_SIZE]> {
    let padding = (WINDOW_SIZE - num_of_bits % WINDOW_SIZE) % WINDOW_SIZE;

    let bits: Vec<bool> = value
        .to_le_bits()
        .into_iter()
        .take(num_of_bits)
        .chain(std::iter::repeat(false).take(padding))
        .collect();
    assert_eq!(bits.len(), num_of_bits + padding);

    bits.chunks_exact(WINDOW_SIZE)
        .map(|x| {
            let mut chunks = [false; WINDOW_SIZE];
            chunks.copy_from_slice(x);
            chunks
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    use group::ff::PrimeFieldBits;
    use halo2_proofs::{
        arithmetic::FieldExt,
        circuit::{floor_planner, Value},
        dev::{CircuitLayout, MockProver},
        plonk::{Circuit, Fixed},
    };
    use pasta_curves::pallas;

    struct RangeCheckCircuit<
        F: FieldExt + PrimeFieldBits,
        const WINDOW_SIZE: usize,
        const NUM_OF_BITS: usize,
        const NUM_OF_WINDOWS: usize,
    > {
        value: Value<F>,
    }

    impl<
            F: FieldExt + PrimeFieldBits,
            const WINDOW_SIZE: usize,
            const NUM_OF_BITS: usize,
            const NUM_OF_WINDOWS: usize,
        > Circuit<F> for RangeCheckCircuit<F, WINDOW_SIZE, NUM_OF_BITS, NUM_OF_WINDOWS>
    {
        type Config = (RangeCheckConfig, Column<Fixed>);
        type FloorPlanner = floor_planner::V1;

        fn without_witnesses(&self) -> Self {
            Self { value: Value::unknown() }
        }

        fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
            let table_column = meta.lookup_table_column();

            let constants = meta.fixed_column();
            meta.enable_constant(constants);
            meta.enable_equality(constants);

            let f = meta.fixed_column();

            (RangeCheckChip::<F, WINDOW_SIZE>::configure(meta, table_column), f)
        }

        fn synthesize(
            &self,
            config: Self::Config,
            mut layouter: impl Layouter<F>,
        ) -> Result<(), Error> {
            let chip = RangeCheckChip::<F, WINDOW_SIZE>::construct(config.0.clone());

            // construct `WINDOW_SIZE` lookup table
            RangeCheckChip::<F, WINDOW_SIZE>::load_k_table(&mut layouter, config.0.k_values_table)?;

            // chip.witness_range_check(&mut layouter, self.value, 0, NUM_OF_BITS, NUM_OF_WINDOWS)?;

            let element = layouter.assign_region(
                || "fixed",
                |mut region: Region<'_, F>| {
                    let v = Value::known(F::one());
                    let element = region.assign_fixed(|| "fixed element", config.1, 0, || v)?;
                    Ok(element)
                },
            )?;

            chip.copy_range_check(&mut layouter, element, 0, NUM_OF_BITS, NUM_OF_WINDOWS)
        }
    }

    #[test]
    fn range_check_64bit() {
        let valid = vec![
            pallas::Base::zero(),
            pallas::Base::one(),
            pallas::Base::from(u64::MAX),
            pallas::Base::from(rand::random::<u64>()),
        ];

        let invalid = vec![
            -pallas::Base::one(),
            pallas::Base::from_u128(u64::MAX as u128 + 1),
            -pallas::Base::from(u64::MAX),
        ];

        let k = 5;

        use plotters::prelude::*;
        let circuit = RangeCheckCircuit::<pallas::Base, 3, 64, 22> {
            value: Value::known(pallas::Base::one()),
        };
        let root = BitMapBackend::new("target/rangecheck64_circuit_layout.png", (3840, 2160))
            .into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Range Check (64-bit) Circuit Layout", ("sans-serif", 60)).unwrap();
        CircuitLayout::default().render(k, &circuit, &root).unwrap();

        for val in valid {
            println!("64-bit range check for {:?}", val);
            let circuit = RangeCheckCircuit::<pallas::Base, 3, 64, 22> { value: Value::known(val) };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            prover.assert_satisfied();
        }

        for val in invalid {
            println!("64-bit range check for {:?}", val);
            let circuit = RangeCheckCircuit::<pallas::Base, 3, 64, 22> { value: Value::known(val) };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert!(prover.verify().is_err());
        }
    }

    #[test]
    fn range_check_128bit() {
        let valid = vec![
            pallas::Base::zero(),
            // pallas::Base::one(),
            // pallas::Base::from_u128(u128::MAX),
            // pallas::Base::from_u128(rand::random::<u128>()),
        ];

        let invalid = vec![
            // pallas::Base::from_u128(u128::MAX) + pallas::Base::one(),
            // -pallas::Base::from_u128(u128::MAX),
        ];

        let k = 6;

        use plotters::prelude::*;
        let circuit = RangeCheckCircuit::<pallas::Base, 3, 128, 43> {
            value: Value::known(pallas::Base::one()),
        };
        let root = BitMapBackend::new("target/rangecheck128_circuit_layout.png", (3840, 2160))
            .into_drawing_area();
        root.fill(&WHITE).unwrap();
        let root = root.titled("Range Check (128-bit) Circuit Layout", ("sans-serif", 60)).unwrap();
        CircuitLayout::default().render(k, &circuit, &root).unwrap();

        for val in valid {
            println!("128-bit range check for {:?}", val);
            let circuit =
                RangeCheckCircuit::<pallas::Base, 3, 128, 43> { value: Value::known(val) };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            prover.assert_satisfied();
        }

        for val in invalid {
            println!("128-bit range check for {:?}", val);
            let circuit =
                RangeCheckCircuit::<pallas::Base, 3, 128, 43> { value: Value::known(val) };
            let prover = MockProver::run(k, &circuit, vec![]).unwrap();
            assert!(prover.verify().is_err());
        }
    }

    // #[test]
    // fn range_check_253bit() {
    //     use group::ff::PrimeField;

    //     let valid = vec![
    //         pallas::Base::zero(),
    //         pallas::Base::one(),
    //         // 2^253 - 1
    //         pallas::Base::from_str_vartime(
    //             "14474011154664524427946373126085988481658748083205070504932198000989141204991",
    //         )
    //         .unwrap(),
    //         // 2^253 / 2
    //         pallas::Base::from_str_vartime(
    //             "7237005577332262213973186563042994240829374041602535252466099000494570602496",
    //         )
    //         .unwrap(),
    //     ];

    //     let k = 7;

    //     use plotters::prelude::*;
    //     let circuit = RangeCheckCircuit::<pallas::Base, 3, 253, 85> {
    //         value: Value::known(pallas::Base::one()),
    //     };
    //     let root = BitMapBackend::new("target/rangecheck253_circuit_layout.png", (3840, 2160))
    //         .into_drawing_area();
    //     root.fill(&WHITE).unwrap();
    //     let root = root.titled("Range Check (253-bit) Circuit Layout", ("sans-serif", 60)).unwrap();
    //     CircuitLayout::default().render(k, &circuit, &root).unwrap();

    //     for val in valid {
    //         println!("253-bit range check for {:?}", val);
    //         let circuit =
    //             RangeCheckCircuit::<pallas::Base, 3, 253, 85> { value: Value::known(val) };
    //         let prover = MockProver::run(k, &circuit, vec![]).unwrap();
    //         prover.assert_satisfied();
    //     }
    // }
}
