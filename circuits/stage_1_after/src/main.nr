use poseidon::poseidon2::Poseidon2;

fn commit_dob(dob: u32) -> Field {
    Poseidon2::hash([dob as Field], 1)
}

fn compute_nullifier(nsk: Field, dob_commitment: Field, app_silo: Field, request_id: Field) -> Field {
    Poseidon2::hash([nsk, dob_commitment, app_silo, request_id], 4)
}


fn main(
    cutoff: pub u32,              // today - 18y, computed by verifier
    app_silo: pub Field,          // Domain ID
    request_id: pub Field,        // Per-request identifier (for uniqueness)
    nullifier: pub Field,         // Must be unique per (app_silo, request_id)
    dob_commitment: pub Field,    // Pre-committed DOB for this account
    dob: u32,                     // Date of birth
    nsk: Field                    // Nullifier secret key (app-siloed)
) {
    //Antifarming at provetime: The DOB used in the proof must equal the pre-committed value.
    let dob_commit_calc = commit_dob(dob);
    assert(dob_commit_calc == dob_commitment);

    // Anti-replay / uniqueness in this context:
    // Nullifier derived from an app-siloed secret key.
    let nullifier_calc = compute_nullifier(nsk, dob_commitment, app_silo, request_id);
    assert(nullifier_calc == nullifier);

    // Business rule: at least 18 years.
    assert(dob <= cutoff);

}
// ---------------------- Unit tests -----------------------------------------

#[test]
fn test_valid_over_18() {
    let dob = 10_000;
    let cutoff = dob + 6570;

    let dob_commit = commit_dob(dob);
    let nsk = 42;
    let app_silo = 12345;
    let request_id = 1;

    let nullifier = compute_nullifier(nsk, dob_commit, app_silo, request_id);

    main(cutoff, app_silo, request_id, nullifier, dob_commit, dob, nsk);
}

#[test(should_fail)]
fn test_invalid_underage() {
    let dob = 25_000;
    let cutoff = 20_000;

    let dob_commit = commit_dob(dob);
    let nsk = 42;
    let app_silo = 12345;
    let request_id = 777;

    let nullifier = compute_nullifier(nsk, dob_commit, app_silo, request_id);

    main(cutoff, app_silo, request_id, nullifier, dob_commit, dob, nsk);
}


#[test]
fn test_edge_exactly_6570_days() {
    let dob = 50_000;
    let cutoff = dob + 6570;

    let dob_commit = commit_dob(dob);
    let nsk = 42;
    let app_silo = 12345;
    let request_id = 3;

    let nullifier = compute_nullifier(nsk, dob_commit, app_silo, request_id);

    main(cutoff, app_silo, request_id, nullifier, dob_commit, dob, nsk);
}


#[test(should_fail)]
fn test_edge_off_by_one_6569_days() {
    let dob = 50_000;
    let cutoff = dob - 6569;

    let dob_commit = commit_dob(dob);
    let nsk = 42;
    let app_silo = 12345;
    let request_id = 778;

    let nullifier = compute_nullifier(nsk, dob_commit, app_silo, request_id);

    main(cutoff, app_silo, request_id, nullifier, dob_commit, dob, nsk);
}


#[test]
fn test_same_dob_different_request_new_nullifier() {
    let dob = 70_000;
    let cutoff = dob + 6570;

    let dob_commit = commit_dob(dob);
    let nsk = 42;
    let app_silo = 12345;

    // first request
    let request_id1 = 100;
    let nullifier1 = compute_nullifier(nsk, dob_commit, app_silo, request_id1);
    main(cutoff, app_silo, request_id1, nullifier1, dob_commit, dob, nsk);

    let request_id2 = 101;
    let nullifier2 = compute_nullifier(nsk, dob_commit, app_silo, request_id2);
    main(cutoff, app_silo, request_id2, nullifier2, dob_commit, dob, nsk);
}
