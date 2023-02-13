// env RAYON_NUM_THREADS=12 cargo bench --all-features
#[macro_use]
extern crate criterion;

use ark_ec::CurveCycle;
use ark_ff::ToBytes;
use ark_ff::{biginteger::BigInteger256, fields::PrimeField};
use ark_pallas::{constraints::GVar as PallasGVar, fr::Fr, Affine as PallasGAffine};
use ark_pcd::{
    r1cs_nark_pcd::{R1CSNarkPCD, R1CSNarkPCDConfig},
    PCD,
};
use ark_sponge::poseidon::constraints::PoseidonSpongeVar;
use ark_sponge::poseidon::PoseidonSponge;
use ark_std::collections::BTreeMap;
use ark_std::io::Cursor;
use ark_std::marker::PhantomData;
use ark_std::time::Duration;
use ark_vesta::{constraints::GVar as VestaGVar, Affine as VestaGAffine};
use criterion::{BenchmarkId, Criterion};
use derecho::{
    building_blocks::{
        crh::{
            poseidon::{PoseidonCRHforMerkleTree, PoseidonCRHforMerkleTreeGadget},
            CRHforMerkleTree,
        },
        mt::{merkle_sparse_tree::MerkleSparseTreeConfig, SparseMT},
    },
    compiler::circuit_specific_setup_compiler::CircuitSpecificSetupDerechoCompiler,
    derecho::{
        disclosure::VerifiableDisclosureConfig,
        state::{AuxState, State},
        transfer::ExampleTransfer,
    },
};
use rand_chacha::ChaChaRng;

pub struct PastaCycle;
impl CurveCycle for PastaCycle {
    type E1 = PallasGAffine;
    type E2 = VestaGAffine;
}

pub struct PCDPoseidonPasta;
impl R1CSNarkPCDConfig<PastaCycle> for PCDPoseidonPasta {
    type MainCurveVar = PallasGVar;
    type HelpCurveVar = VestaGVar;
    type MainSponge = PoseidonSponge<ark_pallas::fr::Fr>;
    type MainSpongeVar = PoseidonSpongeVar<ark_pallas::fr::Fr>;
    type HelpSponge = PoseidonSponge<ark_vesta::fr::Fr>;
    type HelpSpongeVar = PoseidonSpongeVar<ark_vesta::fr::Fr>;
}

type H = PoseidonCRHforMerkleTree<ChaChaRng, Fr>;
type HG = PoseidonCRHforMerkleTreeGadget<ChaChaRng, Fr>;

fn bench_all(c: &mut Criterion) {
    let mut group = c.benchmark_group("disclosures");
    let d = 20;
    println!("benchmarking with merkle tree depth d = {d}");

    #[derive(Clone, Debug)]
    struct P;
    impl MerkleSparseTreeConfig for P {
        const HEIGHT: u64 = 20;
        type H = H;
    }

    struct VCTemplate<I: PCD<Fr>> {
        i_phantom: PhantomData<I>,
    }

    impl<I: PCD<Fr>> VerifiableDisclosureConfig for VCTemplate<I> {
        type F = Fr;
        type H = H;
        type HG = HG;
        type MTMember = SparseMT<Self::F, P, HG>;
        type MTDeposit = SparseMT<Self::F, P, HG>;
        type MTTransfer = SparseMT<Self::F, P, HG>;
        type I = I;
    }

    type TestPCD = R1CSNarkPCD<PastaCycle, PCDPoseidonPasta>;

    type VC = VCTemplate<TestPCD>;

    let mut rng = ark_std::test_rng();
    let al_id = Fr::from_repr(BigInteger256::from(1u64)).unwrap();

    println!("\nrunning setup...");
    let pp = CircuitSpecificSetupDerechoCompiler::circuit_specific_setup(&mut rng, al_id).unwrap();
    let mut derecho = CircuitSpecificSetupDerechoCompiler::make_ds(&pp, &mut rng).unwrap();
    // benchmark setup
    group.bench_with_input(BenchmarkId::new("Setup/".to_string(), d), &d, |b, &_d| {
        b.iter(|| CircuitSpecificSetupDerechoCompiler::make_ds(&pp, &mut rng))
    });

    let mut state = State::<VC>::default();
    let mut aux_state = AuxState::<VC>::default();

    /* setup aux state with placeholder records */
    let mut deposit_map: BTreeMap<u64, Fr> = BTreeMap::new();
    let mut member_map: BTreeMap<u64, Fr> = BTreeMap::new();
    let mut transfer_map: BTreeMap<u64, Fr> = BTreeMap::new();
    let mut old_deposit_map: BTreeMap<u64, Fr> = BTreeMap::new();
    let mut old_member_map: BTreeMap<u64, Fr> = BTreeMap::new();
    let mut old_transfer_map: BTreeMap<u64, Fr> = BTreeMap::new();
    for i in 0..32u64 {
        let addr = i * 2;
        let deposit_val = <<VC as VerifiableDisclosureConfig>::H as CRHforMerkleTree>::hash_bytes(
            &pp.pp_crh, &[0u8; 64],
        )
        .unwrap();
        deposit_map.insert(addr, deposit_val);
        old_deposit_map.insert(addr, deposit_val);
        state.write_deposit(&addr, &deposit_val).unwrap();
        let member_val = <<VC as VerifiableDisclosureConfig>::H as CRHforMerkleTree>::hash_bytes(
            &pp.pp_crh, &[2u8; 64],
        )
        .unwrap();
        member_map.insert(addr, member_val);
        old_member_map.insert(addr, member_val);
        state.write_member(&addr, &member_val).unwrap();

        let transfer_val = <<VC as VerifiableDisclosureConfig>::H as CRHforMerkleTree>::hash_bytes(
            &pp.pp_crh, &[4u8; 64],
        )
        .unwrap();
        transfer_map.insert(addr, transfer_val);
        old_transfer_map.insert(addr, transfer_val);
        state.write_transfer(&addr, &transfer_val).unwrap();
    }

    /* setup aux state with initial commitment, member declaration, and deposit record */
    let init_amt = Fr::from_repr(BigInteger256::from(1021u64)).unwrap();
    let init_pk = Fr::from_repr(BigInteger256::from(1000u64)).unwrap();
    let init_r = Fr::from_repr(BigInteger256::from(1006u64)).unwrap();

    /* compute member decl from allowlist id and init_pk */
    let mut al_id_writer = Cursor::new(Vec::<u8>::new());
    al_id.write(&mut al_id_writer).unwrap();
    let mut init_pk_writer = Cursor::new(Vec::<u8>::new());
    init_pk.write(&mut init_pk_writer).unwrap();
    let member_val = <<VC as VerifiableDisclosureConfig>::H as CRHforMerkleTree>::hash_bytes(
        &pp.pp_crh,
        &[al_id_writer.into_inner(), init_pk_writer.into_inner()].concat(),
    )
    .unwrap();

    let member_key = 64u64;
    member_map.insert(member_key, member_val);
    old_member_map.insert(member_key, member_val);
    state.write_member(&member_key, &member_val).unwrap();

    /* compute input commitment from opening */
    let mut in_cm_amt_writer = Cursor::new(Vec::<u8>::new());
    init_amt.write(&mut in_cm_amt_writer).unwrap();
    let mut in_cm_pk_writer = Cursor::new(Vec::<u8>::new());
    init_pk.write(&mut in_cm_pk_writer).unwrap();
    let mut in_cm_r_writer = Cursor::new(Vec::<u8>::new());
    init_r.write(&mut in_cm_r_writer).unwrap();
    let in_cm = <<VC as VerifiableDisclosureConfig>::H as CRHforMerkleTree>::hash_bytes(
        &pp.pp_crh,
        &[
            in_cm_amt_writer.into_inner(),
            in_cm_pk_writer.into_inner(),
            in_cm_r_writer.into_inner(),
        ]
        .concat(),
    )
    .unwrap();

    /* compute deposit record from amt, pk, in_cm, deposit_uid */
    let deposit_uid = Fr::from_repr(BigInteger256::from(1789u64)).unwrap();
    let mut dep_amt_writer = Cursor::new(Vec::<u8>::new());
    init_amt.write(&mut dep_amt_writer).unwrap();
    let mut dep_pk_writer = Cursor::new(Vec::<u8>::new());
    init_pk.write(&mut dep_pk_writer).unwrap();
    let mut dep_cm_writer = Cursor::new(Vec::<u8>::new());
    in_cm.write(&mut dep_cm_writer).unwrap();
    let mut dep_uid_writer = Cursor::new(Vec::<u8>::new());
    deposit_uid.write(&mut dep_uid_writer).unwrap();
    let deposit_val = <<VC as VerifiableDisclosureConfig>::H as CRHforMerkleTree>::hash_bytes(
        &pp.pp_crh,
        &[
            dep_amt_writer.into_inner(),
            dep_pk_writer.into_inner(),
            dep_cm_writer.into_inner(),
            dep_uid_writer.into_inner(),
        ]
        .concat(),
    )
    .unwrap();

    let deposit_key = 64u64;
    deposit_map.insert(deposit_key, deposit_val);
    old_deposit_map.insert(deposit_key, deposit_val);
    state.write_deposit(&deposit_key, &deposit_val).unwrap();

    aux_state
        .init(&pp.pp_mt.0, &pp.pp_mt.1, &pp.pp_mt.2)
        .unwrap();
    aux_state
        .seed(
            64u64,
            init_amt,
            init_pk,
            init_r,
            &pp.pp_mt.0,
            &member_map,
            &old_member_map,
            &pp.pp_mt.1,
            &deposit_map,
            &old_deposit_map,
            &pp.pp_mt.2,
            &transfer_map,
            &old_transfer_map,
        )
        .unwrap();

    /* now, start to run initial transaction */
    let tx_1 = ExampleTransfer::<VC> {
        out_pk: Fr::from_repr(BigInteger256::from(1001u64)).unwrap(),
        out_amt: Fr::from_repr(BigInteger256::from(1021u64)).unwrap(),
        out_rand: Fr::from_repr(BigInteger256::from(1005u64)).unwrap(),
        member_key,
        member_val,
        deposit_key,
        deposit_val,
        deposit_uid,
        base_case: true,
    };
    println!("\nrunning tx_1...");
    derecho
        .vd
        .run(&mut state, &mut aux_state, &tx_1, &mut rng)
        .unwrap();

    /* obtain information from aux_state */
    let (t_mid, tx_info_mid, acc_info_mid, proof_mid) =
        derecho.vd.info(&state, &aux_state).unwrap();

    assert!(derecho
        .vd
        .verify(
            tx_info_mid.as_ref().unwrap(),
            acc_info_mid.as_ref().unwrap(),
            proof_mid.as_ref().unwrap()
        )
        .unwrap());

    /* read transfer records */
    let val_1 = *state.read_transfer(&64u64).unwrap();
    assert_ne!(val_1, state.default_data);

    let val_default_1 = *state.read_transfer(&t_mid).unwrap();
    assert_eq!(val_default_1, state.default_data);

    let old_member_map2 = state.member_map.clone();
    let old_deposit_map2 = state.deposit_map.clone();
    let old_transfer_map2 = state.transfer_map.clone();

    /* insert more placeholder records */
    for i in 0..31u64 {
        let addr = 66 + i * 2;
        let deposit_val = <<VC as VerifiableDisclosureConfig>::H as CRHforMerkleTree>::hash_bytes(
            &pp.pp_crh, &[0u8; 64],
        )
        .unwrap();
        state.write_deposit(&addr, &deposit_val).unwrap();

        let member_val = <<VC as VerifiableDisclosureConfig>::H as CRHforMerkleTree>::hash_bytes(
            &pp.pp_crh, &[2u8; 64],
        )
        .unwrap();
        state.write_member(&addr, &member_val).unwrap();

        let transfer_val = <<VC as VerifiableDisclosureConfig>::H as CRHforMerkleTree>::hash_bytes(
            &pp.pp_crh, &[4u8; 64],
        )
        .unwrap();
        state.write_transfer(&addr, &transfer_val).unwrap();
    }

    aux_state
        .init(&pp.pp_mt.0, &pp.pp_mt.1, &pp.pp_mt.2)
        .unwrap();
    let private_tx_info = aux_state.private_tx_info.as_ref().unwrap();
    aux_state
        .seed(
            128u64,
            private_tx_info.out_amt,
            private_tx_info.out_pk,
            private_tx_info.out_rand,
            &pp.pp_mt.0,
            &state.member_map,
            &old_member_map2,
            &pp.pp_mt.1,
            &state.deposit_map,
            &old_deposit_map2,
            &pp.pp_mt.2,
            &state.transfer_map,
            &old_transfer_map2,
        )
        .unwrap();

    aux_state
        .init(&pp.pp_mt.0, &pp.pp_mt.1, &pp.pp_mt.2)
        .unwrap();
    let private_tx_info = aux_state.private_tx_info.as_ref().unwrap();
    aux_state
        .seed(
            128u64,
            private_tx_info.out_amt,
            private_tx_info.out_pk,
            private_tx_info.out_rand,
            &pp.pp_mt.0,
            &state.member_map,
            &old_member_map2,
            &pp.pp_mt.1,
            &state.deposit_map,
            &old_deposit_map2,
            &pp.pp_mt.2,
            &state.transfer_map,
            &old_transfer_map2,
        )
        .unwrap();

    /* run subsequent transaction */
    let tx_2 = ExampleTransfer::<VC> {
        out_pk: Fr::from_repr(BigInteger256::from(2001u64)).unwrap(),
        out_amt: Fr::from_repr(BigInteger256::from(2021u64)).unwrap(),
        out_rand: Fr::from_repr(BigInteger256::from(2005u64)).unwrap(),
        member_key,
        member_val,
        deposit_key,
        deposit_val,
        deposit_uid,
        base_case: false,
    };
    println!("\nrunning tx_2...");
    derecho
        .vd
        .run(&mut state, &mut aux_state, &tx_2, &mut rng)
        .unwrap();

    /* obtain information from aux_state */
    let (_t_mid, tx_info_mid, acc_info_mid, proof_mid) =
        derecho.vd.info(&state, &aux_state).unwrap();

    // benchmark prove
    group.bench_with_input(BenchmarkId::new("Prove/".to_string(), d), &d, |b, &_d| {
        b.iter(|| {
            derecho
                .vd
                .run(&mut state, &mut aux_state, &tx_2, &mut rng)
                .unwrap();
        })
    });

    // benchmark verify
    group.bench_with_input(BenchmarkId::new("Verify/".to_string(), d), &d, |b, &_d| {
        b.iter(|| {
            assert!(derecho
                .vd
                .verify(
                    tx_info_mid.as_ref().unwrap(),
                    acc_info_mid.as_ref().unwrap(),
                    proof_mid.as_ref().unwrap()
                )
                .unwrap());
        })
    });
}

criterion_group! {
    name=disclosures_benchmarks;
    config=Criterion::default().sample_size(10).measurement_time(Duration::from_secs(40)).warm_up_time(Duration::from_secs(5));
    targets=bench_all,
}

criterion_main! {disclosures_benchmarks}
