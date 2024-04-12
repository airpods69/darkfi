
use std::usize;

use darkfi_sdk::crypto::smt::{MemoryStorageFp, PoseidonFp, SmtMemoryFp, EMPTY_NODES_FP};
use halo2_proofs::{arithmetic::Field, circuit::Value, dev::MockProver, pasta::Fp};
use libc::printf;
use rand::rngs::OsRng;

use darkfi_sdk::crypto::{
    pedersen::{pedersen_commitment_u64, pedersen_commitment_base}, util::fp_mod_fv, Blind, MerkleNode, MerkleTree, PublicKey,
    SecretKey,
};

use halo2_proofs::pasta::pallas;

use darkfi_sdk::crypto::util::poseidon_hash;
use darkfi_sdk::bridgetree::{BridgeTree, Hashable, Level};

use darkfi_sdk::crypto::pasta_prelude::Curve;
use halo2_proofs::arithmetic::CurveAffine;

use darkfi::{
    zk::{
        proof::{ProvingKey, VerifyingKey},
        vm::ZkCircuit,
        vm_heap::{empty_witnesses, Witness},
        Proof
    },
    zkas::ZkBinary,
    Result,
};

use darkfi_serial::Encodable;



#[test]
fn zkvm_merkle_tree() -> Result<()> {
    let bincode = include_bytes!("../proof/inclusion_proof.zk.bin");
    let zkbin = ZkBinary::decode(bincode)?;

    // Fill the merkle tree with some random coins that we want to witness,
    // and also add the above coin.
    let mut tree = MerkleTree::new(10);
    let coin0 = MerkleNode::from(pallas::Base::random(&mut OsRng));
    let coin1 = MerkleNode::from(pallas::Base::random(&mut OsRng));
    let coin3 = MerkleNode::from(pallas::Base::random(&mut OsRng));

    tree.append(coin0);
    tree.append(coin1);
    tree.append(coin3);


    // ======
    // Prover
    // ======

    let k = zkbin.k;

    let coin2 = pallas::Base::random(&mut OsRng);

    tree.append(MerkleNode::from(coin2));
    let leaf_position = tree.mark().unwrap();

    // Witness values
    let merkle_path = tree.witness(leaf_position, 0).unwrap();
    let leaf_position: u64 = leaf_position.into();
    let blind = pallas::Base::random(&mut OsRng);

    let prover_witnesses = vec![
        Witness::Base(Value::known(coin2)),
        Witness::Uint32(Value::known(leaf_position.try_into().unwrap())),
        Witness::MerklePath(Value::known(merkle_path.clone().try_into().unwrap())),
        Witness::Base(Value::known(blind)),
    ];


    let merkle_root = {
        let position: u64 = leaf_position.into();
        let mut current = MerkleNode::from(coin2);
        for (level, sibling) in merkle_path.iter().enumerate() {
            let level = level as u8;
            current = if position & (1 << level) == 0 {
                MerkleNode::combine(level.into(), &current, sibling)
            } else {
                MerkleNode::combine(level.into(), sibling, &current)
            };
        }
        current
    };

    let enc_leaf = poseidon_hash([coin2, blind]);
    let public_inputs = vec![merkle_root.inner(), enc_leaf];

    // Create the circuit
    let circuit = ZkCircuit::new(prover_witnesses, &zkbin.clone());

    let now = std::time::Instant::now();
    let proving_key = ProvingKey::build(k, &circuit);
    println!("ProvingKey built [{} s]", now.elapsed().as_secs_f64());
    let now = std::time::Instant::now();
    let proof = Proof::create(&proving_key, &[circuit], &public_inputs, &mut OsRng)?;
    println!("Proof created [{} s]", now.elapsed().as_secs_f64());


    // ========
    // Verifier
    // ========

    // Construct empty witnesses
    let verifier_witnesses = empty_witnesses(&zkbin).unwrap();

    // Create the circuit
    let circuit = ZkCircuit::new(verifier_witnesses, &zkbin);

    let verifying_key = VerifyingKey::build(k, &circuit);
    proof.verify(&verifying_key, &public_inputs)?;

    return Ok(());
}

// Works but I don't want to see errors again and again
// #[test]
// fn zkvm_merkle_tree() -> Result<()> {
//     let bincode = include_bytes!("../proof/burn.zk.bin");
//     let zkbin = ZkBinary::decode(bincode)?;
//
//     // ======
//     // Prover
//     // ======
//
//     // Witness values
//     let value = 42;
//     let token_id = pallas::Base::random(&mut OsRng);
//     let value_blind = pallas::Scalar::random(&mut OsRng);
//     let token_blind = pallas::Scalar::random(&mut OsRng);
//     let serial = pallas::Base::random(&mut OsRng);
//     let secret = SecretKey::random(&mut OsRng);
//     let sig_secret = SecretKey::random(&mut OsRng);
//
//     // Build the coin
//     // Replace Coin2 with hash(a, b) -> hash can be anything
//     let a = 10;
//     let b = 9;
//     // let coin2 = Fp::from(10); // Ignoring this for now, I'll change it to a hash later
//     let coin2 = {
//         let (pub_x, pub_y) = PublicKey::from_secret(secret).xy();
//         let messages = [pub_x, pub_y, pallas::Base::from(value), token_id, serial];
//         poseidon_hash(messages)
//     };
//
//     // Fill the merkle tree with some random coins that we want to witness,
//     // and also add the above coin.
//     let mut tree = BridgeTree::<MerkleNode, usize, 32>::new(100);
//     let coin0 = MerkleNode::from(pallas::Base::random(&mut OsRng));
//     let coin1 = MerkleNode::from(pallas::Base::random(&mut OsRng));
//     let coin3 = MerkleNode::from(pallas::Base::random(&mut OsRng));
//
//     tree.append(coin0);
//     // let leaf_position = tree.mark().unwrap();
//     // tree.witness(leaf_position, 0);
//     tree.append(coin1);
//     tree.append(MerkleNode::from(coin2));
//     let leaf_pos = tree.mark().unwrap();
//     tree.append(coin3);
//     // tree.witness();
//
//     let merkle_root = tree.root(0).unwrap();
//     let merkle_path = tree.witness(leaf_pos, 0).unwrap();
//     println!("{:?}", merkle_path);
//     let leaf_pos: u64 = leaf_pos.into();
//
//     let prover_witnesses = vec![
//         Witness::Base(Value::known(secret.inner())),
//         Witness::Base(Value::known(serial)),
//         Witness::Base(Value::known(pallas::Base::from(value))),
//         Witness::Base(Value::known(token_id)),
//         Witness::Scalar(Value::known(value_blind)),
//         Witness::Scalar(Value::known(token_blind)),
//         Witness::Uint32(Value::known(leaf_pos.try_into().unwrap())),
//         Witness::MerklePath(Value::known(merkle_path.try_into().unwrap())),
//         Witness::Base(Value::known(sig_secret.inner())),
//     ];
//
//
//     let value_commit = pedersen_commitment_u64(value, Blind(value_blind));
//     let value_coords = value_commit.to_affine().coordinates().unwrap();
//
//     let token_commit = pedersen_commitment_base(token_id, Blind(token_blind));
//     let token_coords = token_commit.to_affine().coordinates().unwrap();
//
//     let sig_pubkey = PublicKey::from_secret(sig_secret);
//     let (sig_x, sig_y) = sig_pubkey.xy();
//
//
//     let public_inputs = vec![
//         // nullifier.inner(),
//         *value_coords.x(),
//         *value_coords.y(),
//         *token_coords.x(),
//         *token_coords.y(),
//         merkle_root.inner(),
//         sig_x,
//         sig_y,
//     ];
//
//     // Create the circuit
//     let circuit = ZkCircuit::new(prover_witnesses, &zkbin.clone());
//
//     let proving_key = ProvingKey::build(13, &circuit);
//     let proof = Proof::create(&proving_key, &[circuit], &public_inputs, &mut OsRng)?;
//
//     // ========
//     // Verifier
//     // ========
//
//     // Construct empty witnesses
//     let verifier_witnesses = empty_witnesses(&zkbin).unwrap();
//
//     // Create the circuit
//     let circuit = ZkCircuit::new(verifier_witnesses, &zkbin);
//
//     let verifying_key = VerifyingKey::build(13, &circuit);
//     proof.verify(&verifying_key, &public_inputs)?;
//
//     return Ok(());
//
// }
