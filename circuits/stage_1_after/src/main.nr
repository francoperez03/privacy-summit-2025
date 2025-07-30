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

#[test]
fn test_valid_proof() {
    let dob = 10_000;
    let cutoff = 10_000 + 6570; // exactly 18 years later

    let dob_commitment = commit_dob(dob);
    let nsk = 42;
    let app_silo = 12345;
    let request_id = 777;

    let nullifier = compute_nullifier(nsk, dob_commitment, app_silo, request_id);

    main(cutoff, app_silo, request_id, nullifier, dob_commitment, dob, nsk);
}

#[test(should_fail)]
fn test_fails_if_underage() {
    let dob = 20_000;
    let cutoff = 25_000; // only 5 years later -> fails

    let dob_commitment = commit_dob(dob);
    let nsk = 42;
    let app_silo = 12345;
    let request_id = 777;

    let nullifier = compute_nullifier(nsk, dob_commitment, app_silo, request_id);

    main(cutoff, app_silo, request_id, nullifier, dob_commitment, dob, nsk);
}

#[test(should_fail)]
fn test_fails_if_dob_commitment_tampered() {
    let dob = 10_000;
    let cutoff = 20_000;

    let wrong_dob_commitment = commit_dob(9999); // wrong dob
    let nsk = 42;
    let app_silo = 12345;
    let request_id = 777;

    let nullifier = compute_nullifier(nsk, wrong_dob_commitment, app_silo, request_id);

    main(cutoff, app_silo, request_id, nullifier, wrong_dob_commitment, dob, nsk);
}

#[test(should_fail)]
fn test_fails_if_nullifier_wrong() {
    let dob = 10_000;
    let cutoff = 20_000;

    let dob_commitment = commit_dob(dob);
    let nsk = 42;
    let app_silo = 12345;
    let request_id = 777;

    let wrong_nullifier = 0;

    main(cutoff, app_silo, request_id, wrong_nullifier, dob_commitment, dob, nsk);
}
