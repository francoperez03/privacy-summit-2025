use poseidon::poseidon2::Poseidon2;

global DEPTH: u32 = 2;  // Simplified: tree with 4 leaves

// ---- Helpers ---------------------------------------------------------------

fn hash_pair(l: Field, r: Field) -> Field {
    Poseidon2::hash([l, r], 2)
}

// Missing binding - Include account_id in leaf to bind proof to user
// Cross-app reuse - Include app_id in leaf for domain separation
fn make_leaf(
    account_id: Field,
    attr: Field,
    app_id: Field,
) -> Field {
    Poseidon2::hash([account_id, attr, app_id], 3)
}

/// Compute Merkle root from leaf + path using index-derived directions
fn compute_root_from_index(leaf: Field, index: u32, path: [Field; DEPTH]) -> Field {
    let mut digest = leaf;

    for i in 0..DEPTH {
        let sib = path[i];
        let dir = (index >> i) & 1 == 1;
        let (l, r) = if dir { (sib, digest) } else { (digest, sib) };
        digest = hash_pair(l, r);
    }

    digest
}

// Replay attack - Use nullifier to prevent proof reuse
// nullifier = H(nsk, leaf, request_id)
fn calc_nullifier(
    nsk: Field,
    leaf: Field,
    request_id: Field,
) -> Field {
    Poseidon2::hash([nsk, leaf, request_id], 3)
}

// ---- Main circuit ----------------------------------------------------------
// This circuit demonstrates fixes for 3 common vulnerabilities:
// 1. Missing binding: account_id as public input + included in leaf
// 2. Cross-app reuse: app_id included in leaf computation
// 3. Replay attack: nullifier binds proof to specific request

fn main(
    // Public inputs
    account_id: pub Field,    // Binds proof to specific user
    app_id: pub Field,        // Prevents cross-app reuse
    root: pub Field,          // Merkle root
    request_id: pub Field,    // Binds proof to specific request
    nullifier: pub Field,     // Prevents replay (verifier tracks seen nullifiers)

    // Private inputs
    attr: Field,              // User's private attribute (e.g., age, tier)
    nsk: Field,               // Nullifier secret key
    index: u32,               // Position in tree
    path: [Field; DEPTH],     // Merkle proof
) {
    // 1) Compute leaf with binding and domain separation
    //    - account_id: binds to user (prevents Alice's proof used by Bob)
    //    - app_id: prevents proof reuse across different apps
    let leaf = make_leaf(account_id, attr, app_id);

    // 2) Verify Merkle inclusion
    let calc_root = compute_root_from_index(leaf, index, path);
    assert(calc_root == root);

    // 3) Verify nullifier to prevent replay attacks
    //    - Different request_id = different nullifier
    //    - Verifier must track seen nullifiers and reject duplicates
    let nf_calc = calc_nullifier(nsk, leaf, request_id);
    assert(nf_calc == nullifier);
}

// ---- Test helpers ----------------------------------------------------------

fn fake_path() -> [Field; DEPTH] {
    [11, 22]  // 2 levels for DEPTH=2
}

fn build_test_case() -> (
    // publics
    Field, Field, Field, Field, Field,
    // privates
    Field, Field, u32, [Field; DEPTH],
) {
    // Public inputs
    let account_id = 7777;
    let app_id = 1001;
    let request_id = 5555;

    // Private inputs
    let attr = 25;  // e.g., age
    let nsk = 424242;
    let index: u32 = 2;  // binary: 10
    let path = fake_path();

    // Build leaf and root
    let leaf = make_leaf(account_id, attr, app_id);
    let root = compute_root_from_index(leaf, index, path);
    let nullifier = calc_nullifier(nsk, leaf, request_id);

    (
        // publics
        account_id, app_id, root, request_id, nullifier,
        // privates
        attr, nsk, index, path
    )
}

// ---------------------- Unit tests -----------------------------------------

#[test]
fn test_valid_proof() {
    let (
        account_id, app_id, root, request_id, nullifier,
        attr, nsk, index, path
    ) = build_test_case();

    main(account_id, app_id, root, request_id, nullifier, attr, nsk, index, path);
}

#[test(should_fail)]
fn test_attack_wrong_account_id() {
    // Attack: Bob tries to use Alice's proof by changing account_id
    let (
        mut account_id, app_id, root, request_id, nullifier,
        attr, nsk, index, path
    ) = build_test_case();

    account_id = 9999;  // Bob's account_id != Alice's

    // Should fail: leaf won't match because account_id is in the leaf hash
    main(account_id, app_id, root, request_id, nullifier, attr, nsk, index, path);
}

#[test(should_fail)]
fn test_attack_cross_app_reuse() {
    // Attack: Reuse proof from App A in App B
    let (
        account_id, mut app_id, root, request_id, nullifier,
        attr, nsk, index, path
    ) = build_test_case();

    app_id = 2002;  // Different app_id

    // Should fail: leaf won't match because app_id is in the leaf hash
    main(account_id, app_id, root, request_id, nullifier, attr, nsk, index, path);
}

#[test(should_fail)]
fn test_attack_replay() {
    // Attack: Reuse same proof for different request
    let (
        account_id, app_id, root, mut request_id, nullifier,
        attr, nsk, index, path
    ) = build_test_case();

    request_id = 6666;  // Different request_id

    // Should fail: nullifier won't match because request_id changed
    main(account_id, app_id, root, request_id, nullifier, attr, nsk, index, path);
}

#[test]
fn test_different_requests_generate_different_nullifiers() {
    // Same user can make multiple proofs with different nullifiers
    let (
        account_id, app_id, root, request_id_1, nullifier_1,
        attr, nsk, index, path
    ) = build_test_case();

    // First proof
    main(account_id, app_id, root, request_id_1, nullifier_1, attr, nsk, index, path);

    // Second proof with different request_id
    let request_id_2 = request_id_1 + 1;
    let leaf = make_leaf(account_id, attr, app_id);
    let nullifier_2 = calc_nullifier(nsk, leaf, request_id_2);

    // Nullifiers must be different
    assert(nullifier_1 != nullifier_2);

    main(account_id, app_id, root, request_id_2, nullifier_2, attr, nsk, index, path);
}
