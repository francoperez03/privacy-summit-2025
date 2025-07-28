use std::hash::poseidon2::Poseidon2;

const DEPTH: u32 = 4;
const DEPTH_USIZE: usize = 4;

// ---- Helpers ---------------------------------------------------------------

fn hash_pair(l: Field, r: Field) -> Field {
    Poseidon2::hash([l, r], 2)
}

/// Derive direction bit from index (true = right child, false = left child).
fn dir_bit(index: u32, i: u32) -> bool {
    ((index >> i) & 1) == 1
}

/// Structured, domain-separated leaf:
/// leaf = H(TAG_LEAF, app_id, group_id, account_id, attr, version)
fn make_leaf(
    app_id: Field,
    group_id: Field,
    account_id: Field,
    attr: Field,
    version: Field,
) -> Field {
    let TAG_LEAF: Field = 1 as Field;
    Poseidon2::hash([TAG_LEAF, app_id, group_id, account_id, attr, version], 6)
}

/// Compute Merkle root from leaf + path using index-derived directions.
fn compute_root_from_index(leaf: Field, index: u32, path: [Field; DEPTH_USIZE]) -> Field {
    let mut digest = leaf;
    let mut i = 0u32;
    while i < DEPTH {
        let sib = path[i as usize];
        let (l, r) = if dir_bit(index, i) { (sib, digest) } else { (digest, sib) };
        digest = hash_pair(l, r);
        i += 1;
    }
    digest
}

/// Consume-once nullifier (Aztec style):
/// nullifier = H(TAG_NF, nsk, leaf, app_silo, epoch_id, request_id)
fn calc_nullifier(
    nsk: Field,
    leaf: Field,
    app_silo: Field,
    epoch_id: Field,
    request_id: Field,
) -> Field {
    let TAG_NF: Field = 2 as Field;
    Poseidon2::hash([TAG_NF, nsk, leaf, app_silo, epoch_id, request_id], 6)
}

// ---- Main circuit ----------------------------------------------------------

fn main(
    // Publics (binding + freshness + consume-once)
    app_id: pub Field,
    group_id: pub Field,
    version: pub Field,
    root: pub Field,
    app_silo: pub Field,
    epoch_id: pub Field,
    request_id: pub Field,
    nullifier: pub Field,

    // Privates
    account_id: Field,
    attr: Field,
    nsk: Field,
    index: u32,
    path: [Field; DEPTH_USIZE],
) {
    // Hardening: optional bound on index (avoid out-of-range)
    // 1 << DEPTH = 16 para DEPTH=4
    assert(index < (1u32 << DEPTH));

    // 1) Structured leaf with domain separation (binds to user + app context)
    let leaf = make_leaf(app_id, group_id, account_id, attr, version);

    // 2) Merkle inclusion against committed root
    let calc_root = compute_root_from_index(leaf, index, path);
    assert(calc_root == root);

    // 3) Consume-once: public nullifier (verifier must track seen set)
    let nf_calc = calc_nullifier(nsk, leaf, app_silo, epoch_id, request_id);
    assert(nf_calc == nullifier);
}

fn fake_path() -> [Field; DEPTH_USIZE] {
    [11, 22, 33, 44]
}

fn build_publics_and_proof() -> (
    // publics
    Field, Field, Field, Field, Field, Field, Field, Field,
    // privates
    Field, Field, Field, u32, [Field; DEPTH_USIZE],
) {
    // Context / bindings
    let app_id = 1001;
    let group_id = 2002;
    let version = 1;

    // Freshness / domain / request
    let app_silo = 3003;
    let epoch_id = 4444;
    let request_id = 5555;

    // User data
    let account_id = 7777;
    let attr = 8888;   // e.g. some attribute
    let nsk = 424242;

    // Membership proof
    let index: u32 = 6; // binary 0110 → dir pattern: [0,1,1,0]
    let path = fake_path();

    // Build leaf and root deterministically for this test
    let leaf = make_leaf(app_id, group_id, account_id, attr, version);
    let root = compute_root_from_index(leaf, index, path);

    // Consume-once
    let nullifier = calc_nullifier(nsk, leaf, app_silo, epoch_id, request_id);

    (
        // publics
        app_id, group_id, version, root, app_silo, epoch_id, request_id, nullifier,
        // privates
        account_id, attr, nsk, index, path
    )
}

// Tests ------------------------------------------------------------------

#[test]
fn test_valid_membership_and_nullifier() {
    let (
        app_id, group_id, version, root, app_silo, epoch_id, request_id, nullifier,
        account_id, attr, nsk, index, path
    ) = build_publics_and_proof();

    // Should pass
    main(
        app_id, group_id, version, root, app_silo, epoch_id, request_id, nullifier,
        account_id, attr, nsk, index, path
    );
}

#[test(should_fail)]
fn test_fails_with_wrong_root() {
    let (
        app_id, group_id, version, mut root, app_silo, epoch_id, request_id, nullifier,
        account_id, attr, nsk, index, path
    ) = build_publics_and_proof();

    root += 1; // stale/incorrect root

    main(
        app_id, group_id, version, root, app_silo, epoch_id, request_id, nullifier,
        account_id, attr, nsk, index, path
    );
}

#[test(should_fail)]
fn test_fails_with_wrong_index_direction() {
    let (
        app_id, group_id, version, root, app_silo, epoch_id, request_id, nullifier,
        account_id, attr, nsk, mut index, path
    ) = build_publics_and_proof();

    // Flip one bit of the index → traversal changes → root mismatch
    index ^= 1u32; // toggle LSB

    main(
        app_id, group_id, version, root, app_silo, epoch_id, request_id, nullifier,
        account_id, attr, nsk, index, path
    );
}

#[test(should_fail)]
fn test_fails_with_tampered_leaf_binding() {
    let (
        app_id, group_id, version, root, app_silo, epoch_id, request_id, nullifier,
        mut account_id, attr, nsk, index, path
    ) = build_publics_and_proof();

    // Change account_id → leaf changes → root mismatch
    account_id += 1;

    main(
        app_id, group_id, version, root, app_silo, epoch_id, request_id, nullifier,
        account_id, attr, nsk, index, path
    );
}

#[test(should_fail)]
fn test_fails_with_wrong_nullifier() {
    let (
        app_id, group_id, version, root, app_silo, epoch_id, request_id, mut nullifier,
        account_id, attr, nsk, index, path
    ) = build_publics_and_proof();

    // Break the consume-once property by altering the public nullifier
    nullifier += 1;

    main(
        app_id, group_id, version, root, app_silo, epoch_id, request_id, nullifier,
        account_id, attr, nsk, index, path
    );
}
