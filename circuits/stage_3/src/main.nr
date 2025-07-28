use std::hash::poseidon2::Poseidon2;

// UTXO flow (conceptual)
// -----------------------------------------------------------------------------
// Spend one input note → create two output notes (receiver + change)
// and (conceptually) publish a nullifier for the spent note.
//
// original commit:
//     commit = C(owner_pk_2, value, rho)
//
// Verify inclusion, enforce value conservation: value == value_1 + value_2
// Create new output notes (public commitments):
//     commit1 = C(owner_pk_1, value_1, rho_1)   ← receiver
//     commit2 = C(owner_pk_2, value_2, rho_2)   ← change
//
// (Not implemented here, but typical next step)
//     nullifier = NF(secret_key, leaf, context) → verifier stores & rejects re-use
// -----------------------------------------------------------------------------


global DEPTH: u32 = 2;
const DEPTH_USIZE: usize = 2;

// Hash helper
fn hash_pair(left: Field, right: Field) -> Field {
    Poseidon2::hash([left, right], 2)
}

// Note commitment: C = H(owner_pk, value, rho)
fn note_commit(owner_pk: Field, value: Field, rho: Field) -> Field {
    Poseidon2::hash([owner_pk, value, rho], 3)
}

// Merkle recomputation using a direction selector (true = right)
fn compute_merkle_root(leaf: Field, path: [Field; DEPTH_USIZE], selector: [bool; DEPTH_USIZE]) -> Field {
    let mut digest = leaf;
    for i in 0..DEPTH_USIZE {
        let (left, right) = if selector[i] { (path[i], digest) } else { (digest, path[i]) };
        digest = hash_pair(left, right);
    }
    digest
}

fn main(
    // ── Public ───────────────────────────────────────────
    root: pub Field,        // commitments Merkle root
    commit1: pub Field,     // first output commitment
    commit2: pub Field,     // second output commitment

    // ── Private: input note ─────────────────────────────
    owner_pk: Field,
    value: Field,
    rho: Field,
    path: [Field; DEPTH_USIZE],
    selector: [bool; DEPTH_USIZE],

    // ── Private: output notes ───────────────────────────
    owner_pk_1: Field,
    value_1: Field,
    rho_1: Field,

    owner_pk_2: Field,
    value_2: Field,
    rho_2: Field,
) {
    // 1) Input membership
    let leaf = note_commit(owner_pk, value, rho);
    let calc_root = compute_merkle_root(leaf, path, selector);
    assert(calc_root == root);

    // 2) Value conservation
    assert(value == (value_1 + value_2));

    // 3) Output commitments match publics
    let c1 = note_commit(owner_pk_1, value_1, rho_1);
    let c2 = note_commit(owner_pk_2, value_2, rho_2);
    assert(c1 == commit1);
    assert(c2 == commit2);
}
