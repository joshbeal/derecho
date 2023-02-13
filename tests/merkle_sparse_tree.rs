use ark_ed_on_mnt4_298::EdwardsParameters;
use ark_ed_on_mnt4_298::Fq as Fr;
use ark_std::collections::BTreeMap;
use derecho::building_blocks::{
    crh::bowe_hopwood::{BoweHopwoodCRHforMerkleTree, BoweHopwoodCRHforMerkleTreeGadget},
    mt::{merkle_sparse_tree::MerkleSparseTreeConfig, SparseMT, MT},
};
use rand_chacha::ChaChaRng;

#[test]
fn test_merkle_sparse_tree_pedersen() {
    type H = BoweHopwoodCRHforMerkleTree<ChaChaRng, EdwardsParameters>;
    type HG = BoweHopwoodCRHforMerkleTreeGadget<ChaChaRng, EdwardsParameters>;

    #[derive(Clone, Debug)]
    struct P;
    impl MerkleSparseTreeConfig for P {
        const HEIGHT: u64 = 32;
        type H = H;
    }

    type M = SparseMT<Fr, P, HG>;

    let mut rng = ark_std::test_rng();

    let pp = M::setup(&mut rng).unwrap();

    /* tree_1 is empty initially */
    let mut tree_1 = M::new::<u8>(&pp).unwrap();
    let empty_tree_rh = M::root(&pp, &tree_1).unwrap();
    assert!(M::validate(&pp, &tree_1).unwrap());

    /* tree_1 + (1, 2), (2, 4), (3, 7) */
    let waddr = vec![1u64, 2, 3];
    let wdata = vec![2u8, 4, 7];
    let (tree_1_rh, tree_1_modify_proof) =
        M::_modify_and_apply(&pp, &mut tree_1, &waddr, &wdata, false).unwrap();

    let mut tree_1_history = M::new::<u8>(&pp).unwrap();
    let _ = M::root(&pp, &tree_1_history).unwrap();
    assert!(M::validate(&pp, &tree_1_history).unwrap());

    /* tree_1_history + (0, 2), (1, hash_0), (2, 4), (1, hash_1), (4, 7), (2, hash_2) */
    let waddr2 = vec![0u64, 2, 4];
    let wdata2 = vec![2u8, 4, 7];
    let (tree_1_history_rh, _) =
        M::_modify_and_apply(&pp, &mut tree_1_history, &waddr2, &wdata2, true).unwrap();

    /* check if the tree_1_rh matches the new rh */
    assert_eq!(tree_1_rh, M::root(&pp, &tree_1).unwrap());

    /* check if the tree_1_history_rh matches the new rh */
    assert_eq!(tree_1_history_rh, M::root(&pp, &tree_1_history).unwrap());

    /* check if the modify proof works */
    assert!(M::verify_modify(
        &pp,
        &empty_tree_rh,
        &tree_1_rh,
        &waddr,
        &wdata,
        &tree_1_modify_proof
    )
    .unwrap());

    /* check if a proof does NOT work when the addr is tampered */
    let waddr_tampered = vec![2u64, 3, 1];
    assert!(!M::verify_modify(
        &pp,
        &empty_tree_rh,
        &tree_1_rh,
        &waddr_tampered,
        &wdata,
        &tree_1_modify_proof
    )
    .unwrap());

    /* check if a proof does NOT work when the data is tampered */
    let wdata_tampered = vec![1u8, 3, 9];
    assert!(!M::verify_modify(
        &pp,
        &empty_tree_rh,
        &tree_1_rh,
        &waddr,
        &wdata_tampered,
        &tree_1_modify_proof
    )
    .unwrap());

    /* check if a proof does NOT work when both addr and data are tampered */
    assert!(!M::verify_modify(
        &pp,
        &empty_tree_rh,
        &tree_1_rh,
        &waddr_tampered,
        &wdata_tampered,
        &tree_1_modify_proof
    )
    .unwrap());

    /* test the _new_with_map */
    let mut data_map: BTreeMap<u64, u8> = BTreeMap::new();
    data_map.insert(waddr[0], wdata[0]);
    data_map.insert(waddr[1], wdata[1]);
    data_map.insert(waddr[2], wdata[2]);

    let tree_2 = M::_new_with_map(&pp, &data_map).unwrap();
    assert_eq!(tree_1_rh, M::root(&pp, &tree_2).unwrap());

    /* test lookup */
    let raddr = vec![1u64, 2, 3];
    let rdata = vec![2u8, 4, 7];
    /* the same as waddr, wdata */

    let lookup_proof = M::lookup(&pp, &tree_1, &raddr).unwrap();
    assert!(M::verify_lookup(&pp, &tree_1_rh, &raddr, &rdata, &lookup_proof).unwrap());

    /* check if a proof does NOT work when the addr is tampered */
    let raddr_tampered = vec![2u64, 3, 1];
    assert!(!M::verify_lookup(&pp, &tree_1_rh, &raddr_tampered, &rdata, &lookup_proof).unwrap());

    /* check if a proof does NOT work when the data is tampered */
    let rdata_tampered = vec![1u8, 3, 9];
    assert!(!M::verify_lookup(&pp, &tree_1_rh, &raddr, &rdata_tampered, &lookup_proof).unwrap());

    /* check if a proof does NOT work when both addr and data are tampered */
    assert!(!M::verify_lookup(
        &pp,
        &tree_1_rh,
        &raddr_tampered,
        &rdata_tampered,
        &lookup_proof
    )
    .unwrap());

    M::clear(&pp, &mut tree_1).unwrap();
}
