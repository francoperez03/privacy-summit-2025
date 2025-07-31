use poseidon::poseidon2::Poseidon2;

global DEPTH: u32 = 4;

// ---- Helpers ---------------------------------------------------------------

fn hash_pair(l: Field, r: Field) -> Field {
    Poseidon2::hash([l, r], 2)
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
fn compute_root_from_index(leaf: Field, index: u32, path: [Field; DEPTH]) -> Field {
    let mut digest = leaf;

    for i in 0..DEPTH {
        let sib = path[i];
        let dir = (index >> (i as u8)) & 1 == 1;
        let (l, r) = if dir { (sib, digest) } else { (digest, sib) };
        digest = hash_pair(l, r);
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
    path: [Field; DEPTH],
) {
    // Hardening: optional bound on index (avoid out-of-range)
    // 1 << DEPTH = 16 for DEPTH=4
    assert(index < (1 << (DEPTH as u8)));

    // 1) Structured leaf with domain separation (binds to user + app context)
    let leaf = make_leaf(app_id, group_id, account_id, attr, version);

    // 2) Merkle inclusion against committed root
    let calc_root = compute_root_from_index(leaf, index, path);
    assert(calc_root == root);

    // 3) Consume-once: public nullifier (verifier must track seen set)
    let nf_calc = calc_nullifier(nsk, leaf, app_silo, epoch_id, request_id);
    assert(nf_calc == nullifier);
}

fn fake_path() -> [Field; DEPTH] {
    [11, 22, 33, 44]
}

fn build_publics_and_proof() -> (
    // publics
    Field, Field, Field, Field, Field, Field, Field, Field,
    // privates
    Field, Field, Field, u32, [Field; DEPTH],
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
    let index: u32 = 6; // binary 0110 -> dir pattern: [0,1,1,0]
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

// ---------------------- Unit tests -----------------------------------------

#[test]
fn test_valid_membership() {
    let (
        app_id, group_id, version, root, app_silo, epoch_id, request_id, nullifier,
        account_id, attr, nsk, index, path
    ) = build_publics_and_proof();

    // Debe pasar
    main(
        app_id, group_id, version, root,
        app_silo, epoch_id, request_id, nullifier,
        account_id, attr, nsk, index, path
    );
}

#[test(should_fail)]
fn test_invalid_not_in_list() {
    let (
        app_id, group_id, version, root, app_silo, epoch_id, request_id, nullifier,
        mut account_id, attr, nsk, index, path
    ) = build_publics_and_proof();

    account_id += 555;

    main(
        app_id, group_id, version, root,
        app_silo, epoch_id, request_id, nullifier,
        account_id, attr, nsk, index, path
    );
}

#[test(should_fail)]
fn test_edge_wrong_path_length() {
    let (
        app_id, group_id, version, root,
        app_silo, epoch_id, request_id, nullifier,
        account_id, attr, nsk, index, mut path
    ) = build_publics_and_proof();

    path[DEPTH] = 0;

    main(
        app_id, group_id, version, root,
        app_silo, epoch_id, request_id, nullifier,
        account_id, attr, nsk, index, path
    );
}


#[test(should_fail)]
fn test_edge_off_by_one_index() {
    let (
        app_id, group_id, version, root, app_silo, epoch_id, request_id, nullifier,
        account_id, attr, nsk, mut index, path
    ) = build_publics_and_proof();

    index ^= 1;

    main(
        app_id, group_id, version, root,
        app_silo, epoch_id, request_id, nullifier,
        account_id, attr, nsk, index, path
    );
}

#[test]
fn test_edge_same_leaf_different_request_new_nullifier() {
    let epoch_id = 4444;

    let (
        app_id, group_id, version, root, app_silo, epoch_id, request_id_1, nullifier_1,
        account_id, attr, nsk, index, path
    ) = build_publics_and_proof();

    main(
        app_id, group_id, version, root,
        app_silo, epoch_id, request_id_1, nullifier_1,
        account_id, attr, nsk, index, path
    );

    let request_id_2 = request_id_1 + 1;
    let nullifier_2 = calc_nullifier(nsk,
                                        make_leaf(app_id, group_id, account_id, attr, version),
                                        app_silo,
                                        epoch_id,
                                        request_id_2);

    // nullifiers deben ser distintos
    assert(nullifier_1 != nullifier_2);

    main(
        app_id, group_id, version, root,
        app_silo, epoch_id, request_id_2, nullifier_2,
        account_id, attr, nsk, index, path
    );
}
