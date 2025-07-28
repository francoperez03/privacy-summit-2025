use std::hash::poseidon2::Poseidon2;

const DEPTH: u32 = 4;
const DEPTH_USIZE: usize = 4;

// ───────────────── Helpers ─────────────────

fn hash2(a: Field, b: Field) -> Field {
    Poseidon2::hash([a, b], 2)
}

// Structured note commitment with domain tag and asset binding:
// C = H(TAG_NOTE, owner_pk, asset_id, value, rho)
fn note_commit(owner_pk: Field, asset_id: Field, value: Field, rho: Field) -> Field {
    let TAG_NOTE: Field = 7;
    Poseidon2::hash([TAG_NOTE, owner_pk, asset_id, value, rho], 5)
}

// Recompute Merkle root using sibling path and direction selector (true = right)
fn compute_merkle_root(
    leaf: Field,
    path: [Field; DEPTH_USIZE],
    selector: [bool; DEPTH_USIZE],
) -> Field {
    let mut d = leaf;
    for i in 0..DEPTH_USIZE {
        let (l, r) = if selector[i] { (path[i], d) } else { (d, path[i]) };
        d = hash2(l, r);
    }
    d
}

// Aztec-style consume-once nullifier with context binding:
// nf = H(TAG_NF, nsk, leaf, app_silo, epoch_id, request_id)
fn calc_nullifier(
    nsk: Field,
    leaf: Field,
    app_silo: Field,
    epoch_id: Field,
    request_id: Field,
) -> Field {
    let TAG_NF: Field = 9;
    Poseidon2::hash([TAG_NF, nsk, leaf, app_silo, epoch_id, request_id], 6)
}

// ───────────────── Circuit ─────────────────

fn main(
    // Publics (binding + membership + consume-once)
    root: pub Field,
    asset_id: pub Field,
    commit1: pub Field,
    commit2: pub Field,
    app_silo: pub Field,
    epoch_id: pub Field,
    request_id: pub Field,
    nullifier: pub Field,

    // Private input note
    owner_pk: Field,
    value: Field,
    rho: Field,
    nsk: Field,
    path: [Field; DEPTH_USIZE],
    selector: [bool; DEPTH_USIZE],

    // Private output notes
    owner_pk_1: Field,
    value_1: Field,
    rho_1: Field,

    owner_pk_2: Field,
    value_2: Field,
    rho_2: Field,
) {
    // 1) Input membership
    let leaf = note_commit(owner_pk, asset_id, value, rho);
    let calc_root = compute_merkle_root(leaf, path, selector);
    assert(calc_root == root);

    // 2) Value conservation and simple bounds
    assert(value == (value_1 + value_2));
    // Basic range sanity: outputs cannot exceed input
    assert(value_1 <= value);
    assert(value_2 <= value);

    // 3) Output commitments must match publics (same asset)
    let c1 = note_commit(owner_pk_1, asset_id, value_1, rho_1);
    let c2 = note_commit(owner_pk_2, asset_id, value_2, rho_2);
    assert(c1 == commit1);
    assert(c2 == commit2);

    // 4) Consume-once nullifier with context binding
    let nf_calc = calc_nullifier(nsk, leaf, app_silo, epoch_id, request_id);
    assert(nf_calc == nullifier);
}

// ───────────────── Tests ─────────────────

fn fake_path() -> [Field; DEPTH_USIZE] {
    [11, 22, 33, 44]
}

fn build_case() -> (
    // publics
    Field, Field, Field, Field, Field, Field, Field, Field,
    // privates
    Field, Field, Field, Field, [Field; DEPTH_USIZE], [bool; DEPTH_USIZE],
    Field, Field, Field,
    Field, Field, Field,
) {
    // Context
    let app_silo = 3003;
    let epoch_id = 4444;
    let request_id = 5555;

    // Asset
    let asset_id = 100;

    // Input note
    let owner_pk = 7777;
    let value = 50;
    let rho = 123;
    let nsk = 424242;

    let path = fake_path();
    // selector pattern (depth=4) e.g. [false, true, true, false]
    let selector = [false, true, true, false];

    // Compute root from input leaf
    let leaf = note_commit(owner_pk, asset_id, value, rho);
    let root = compute_merkle_root(leaf, path, selector);

    // Outputs: split 20 + 30 = 50
    let owner_pk_1 = 8888;
    let value_1 = 20;
    let rho_1 = 9;

    let owner_pk_2 = 9999;
    let value_2 = 30;
    let rho_2 = 10;

    let commit1 = note_commit(owner_pk_1, asset_id, value_1, rho_1);
    let commit2 = note_commit(owner_pk_2, asset_id, value_2, rho_2);

    // Nullifier
    let nullifier = calc_nullifier(nsk, leaf, app_silo, epoch_id, request_id);

    (
        // publics
        root, asset_id, commit1, commit2, app_silo, epoch_id, request_id, nullifier,
        // privates
        owner_pk, value, rho, nsk, path, selector,
        owner_pk_1, value_1, rho_1,
        owner_pk_2, value_2, rho_2
    )
}

#[test]
fn test_valid_spend() {
    let (
        root, asset_id, commit1, commit2, app_silo, epoch_id, request_id, nullifier,
        owner_pk, value, rho, nsk, path, selector,
        owner_pk_1, value_1, rho_1,
        owner_pk_2, value_2, rho_2
    ) = build_case();

    main(
        root, asset_id, commit1, commit2, app_silo, epoch_id, request_id, nullifier,
        owner_pk, value, rho, nsk, path, selector,
        owner_pk_1, value_1, rho_1,
        owner_pk_2, value_2, rho_2
    );
}

#[test(should_fail)]
fn test_fails_wrong_root() {
    let (
        mut root, asset_id, commit1, commit2, app_silo, epoch_id, request_id, nullifier,
        owner_pk, value, rho, nsk, path, selector,
        owner_pk_1, value_1, rho_1,
        owner_pk_2, value_2, rho_2
    ) = build_case();

    root += 1;

    main(
        root, asset_id, commit1, commit2, app_silo, epoch_id, request_id, nullifier,
        owner_pk, value, rho, nsk, path, selector,
        owner_pk_1, value_1, rho_1,
        owner_pk_2, value_2, rho_2
    );
}

#[test(should_fail)]
fn test_fails_conservation() {
    let (
        root, asset_id, _commit1, _commit2, app_silo, epoch_id, request_id, nullifier,
        owner_pk, value, rho, nsk, path, selector,
        owner_pk_1, mut value_1, rho_1,
        owner_pk_2, value_2, rho_2
    ) = build_case();

    // Break: 50 != 25 + 30
    value_1 = 25;
    let commit1_bad = note_commit(owner_pk_1, asset_id, value_1, rho_1);
    let commit2_ok  = note_commit(owner_pk_2, asset_id, value_2, rho_2);

    main(
        root, asset_id, commit1_bad, commit2_ok, app_silo, epoch_id, request_id, nullifier,
        owner_pk, value, rho, nsk, path, selector,
        owner_pk_1, value_1, rho_1,
        owner_pk_2, value_2, rho_2
    );
}

#[test(should_fail)]
fn test_fails_commitment_tamper() {
    let (
        root, asset_id, mut commit1, commit2, app_silo, epoch_id, request_id, nullifier,
        owner_pk, value, rho, nsk, path, selector,
        owner_pk_1, value_1, rho_1,
        owner_pk_2, value_2, rho_2
    ) = build_case();

    commit1 += 1;

    main(
        root, asset_id, commit1, commit2, app_silo, epoch_id, request_id, nullifier,
        owner_pk, value, rho, nsk, path, selector,
        owner_pk_1, value_1, rho_1,
        owner_pk_2, value_2, rho_2
    );
}

#[test(should_fail)]
fn test_fails_nullifier_mismatch_replay() {
    let (
        root, asset_id, commit1, commit2, app_silo, epoch_id, mut request_id, nullifier,
        owner_pk, value, rho, nsk, path, selector,
        owner_pk_1, value_1, rho_1,
        owner_pk_2, value_2, rho_2
    ) = build_case();

    // Replay attempt with different request_id but same nullifier
    request_id += 1;

    main(
        root, asset_id, commit1, commit2, app_silo, epoch_id, request_id, nullifier,
        owner_pk, value, rho, nsk, path, selector,
        owner_pk_1, value_1, rho_1,
        owner_pk_2, value_2, rho_2
    );
}

#[test(should_fail)]
fn test_fails_wrong_selector_path() {
    let (
        root, asset_id, commit1, commit2, app_silo, epoch_id, request_id, nullifier,
        owner_pk, value, rho, nsk, path, mut selector,
        owner_pk_1, value_1, rho_1,
        owner_pk_2, value_2, rho_2
    ) = build_case();

    // Flip one direction bit → recomputed root changes
    selector[0] = !selector[0];

    main(
        root, asset_id, commit1, commit2, app_silo, epoch_id, request_id, nullifier,
        owner_pk, value, rho, nsk, path, selector,
        owner_pk_1, value_1, rho_1,
        owner_pk_2, value_2, rho_2
    );
}

#[test(should_fail)]
fn test_fails_output_exceeds_input() {
    let (
        root, asset_id, _commit1, _commit2, app_silo, epoch_id, request_id, nullifier,
        owner_pk, value, rho, nsk, path, selector,
        owner_pk_1, mut value_1, rho_1,
        owner_pk_2, value_2, rho_2
    ) = build_case();

    // Force value_1 > value (range sanity)
    value_1 = value + 1;
    let commit1_bad = note_commit(owner_pk_1, asset_id, value_1, rho_1);
    let commit2_ok  = note_commit(owner_pk_2, asset_id, value_2, rho_2);

    main(
        root, asset_id, commit1_bad, commit2_ok, app_silo, epoch_id, request_id, nullifier,
        owner_pk, value, rho, nsk, path, selector,
        owner_pk_1, value_1, rho_1,
        owner_pk_2, value_2, rho_2
    );
}
