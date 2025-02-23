use group::ff::Field;
use halo2_curves::bn256::{Bn256, Fr, G1Affine};
use halo2_proofs::circuit::{Cell, Layouter, SimpleFloorPlanner, Value};
use halo2_proofs::plonk::*;
use halo2_proofs::poly::{commitment::ParamsProver, Rotation};
use halo2_proofs::transcript::{Blake2bWrite, Challenge255};

use halo2_proofs::{
    poly::kzg::{
        commitment::{KZGCommitmentScheme, ParamsKZG},
        multiopen::ProverGWC,
    },
    transcript::TranscriptWriterBuffer,
};

use std::marker::PhantomData;

/// This represents an advice column at a certain row in the ConstraintSystem
#[derive(Copy, Clone, Debug)]
#[allow(dead_code)]
pub struct Variable(Column<Advice>, usize);

#[derive(Clone)]
struct PlonkConfig {
    a: Column<Advice>,
    b: Column<Advice>,
    c: Column<Advice>,

    sa: Column<Fixed>,
    sb: Column<Fixed>,
    sc: Column<Fixed>,
    sm: Column<Fixed>,
}

trait StandardCs<FF: Field> {
    fn raw_multiply<F>(
        &self,
        layouter: &mut impl Layouter<FF>,
        f: F,
    ) -> Result<(Cell, Cell, Cell), Error>
    where
        F: FnMut() -> Value<(Assigned<FF>, Assigned<FF>, Assigned<FF>)>;
    fn copy(&self, layouter: &mut impl Layouter<FF>, a: Cell, b: Cell) -> Result<(), Error>;
}

#[derive(Clone)]
struct MyCircuit<F: Field> {
    a: Value<F>,
    k: u32,
}

struct StandardPlonk<F: Field> {
    config: PlonkConfig,
    _marker: PhantomData<F>,
}

impl<FF: Field> StandardPlonk<FF> {
    fn new(config: PlonkConfig) -> Self {
        StandardPlonk {
            config,
            _marker: PhantomData,
        }
    }
}

impl<FF: Field> StandardCs<FF> for StandardPlonk<FF> {
    fn raw_multiply<F>(
        &self,
        layouter: &mut impl Layouter<FF>,
        mut f: F,
    ) -> Result<(Cell, Cell, Cell), Error>
    where
        F: FnMut() -> Value<(Assigned<FF>, Assigned<FF>, Assigned<FF>)>,
    {
        layouter.assign_region(
            || "raw_multiply",
            |mut region| {
                let value;
                let lhs = region.assign_advice(self.config.a, 0, {
                    value = Some(f());
                    value.unwrap().map(|v| v.0)
                });
                let rhs = region.assign_advice(self.config.b, 0, value.unwrap().map(|v| v.1));
                let out = region.assign_advice(self.config.c, 0, value.unwrap().map(|v| v.2));

                region.assign_fixed(self.config.sa, 0, FF::ZERO);
                region.assign_fixed(self.config.sb, 0, FF::ZERO);
                region.assign_fixed(self.config.sc, 0, FF::ONE);
                region.assign_fixed(self.config.sm, 0, FF::ONE);
                Ok((lhs.cell(), rhs.cell(), out.cell()))
            },
        )
    }

    fn copy(&self, layouter: &mut impl Layouter<FF>, left: Cell, right: Cell) -> Result<(), Error> {
        layouter.assign_region(
            || "copy",
            |mut region| {
                region.constrain_equal(left, right);
                Ok(())
            },
        )
    }
}

impl<F: Field> Circuit<F> for MyCircuit<F> {
    type Config = PlonkConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self {
            a: Value::unknown(),
            k: self.k,
        }
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> PlonkConfig {
        meta.set_minimum_degree(5);

        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();

        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(c);

        let sm = meta.fixed_column();
        let sa = meta.fixed_column();
        let sb = meta.fixed_column();
        let sc = meta.fixed_column();

        meta.create_gate("Combined add-mult", |meta| {
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());

            let sa = meta.query_fixed(sa, Rotation::cur());
            let sb = meta.query_fixed(sb, Rotation::cur());
            let sc = meta.query_fixed(sc, Rotation::cur());
            let sm = meta.query_fixed(sm, Rotation::cur());

            vec![a.clone() * sa + b.clone() * sb + a * b * sm - (c * sc)]
        });

        PlonkConfig {
            a,
            b,
            c,
            sa,
            sb,
            sc,
            sm,
        }
    }

    fn synthesize(&self, config: PlonkConfig, mut layouter: impl Layouter<F>) -> Result<(), Error> {
        let cs = StandardPlonk::new(config);

        for _ in 0..((1 << (self.k - 1)) - 3) {
            let a: Value<Assigned<_>> = self.a.into();
            let mut a_squared = Value::unknown();
            let (a0, _, c0) = cs.raw_multiply(&mut layouter, || {
                a_squared = a.square();
                a.zip(a_squared).map(|(a, a_squared)| (a, a, a_squared))
            })?;
            cs.copy(&mut layouter, a0, c0)?;
        }

        Ok(())
    }
}

fn prove(k: u32, params: &ParamsKZG<Bn256>, pk: &ProvingKey<G1Affine>) -> Vec<u8> {
    let mut rng = ark_std::test_rng();

    let circuit: MyCircuit<Fr> = MyCircuit {
        a: Value::known(Fr::random(&mut rng)),
        k,
    };

    let mut transcript = Blake2bWrite::<_, _, Challenge255<G1Affine>>::init(vec![]);
    create_proof::<KZGCommitmentScheme<Bn256>, ProverGWC<Bn256>, _, _, _, _>(
        params,
        pk,
        &[circuit],
        &[&[]],
        &mut rng,
        &mut transcript,
    )
    .expect("proof generation should not fail");
    transcript.finalize()
}

pub fn prover(min_size: usize, max_size: usize) {
    for size in min_size..=max_size {
        let params_kzg = ParamsKZG::new(size as u32);
        let empty_circuit: MyCircuit<Fr> = MyCircuit {
            a: Value::unknown(),
            k: size as u32,
        };
        let vk = keygen_vk(&params_kzg, &empty_circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params_kzg, vk, &empty_circuit).expect("keygen_pk should not fail");

        let _proof = timed!(
            format!("Halo2: Proving for {size}",),
            prove(size as u32, &params_kzg, &pk)
        );
    }
}
