use poseidon::poseidon2::Poseidon2;

fn hash_pair(left: Field, right: Field) -> Field {
    Poseidon2::hash([left, right], 2)
}

fn main(
    leaf: Field,                  // The hashed value to prove is in the list
    path: [Field; 2],             // The sibling nodes for each level
    selector: [bool; 2],          // Direction at each level (true = right)
    root: pub Field               // Merkle root committed by verifier
) {
    let mut digest = leaf;

    for i in 0..2 {
        let (left, right) = if selector[i] {
            (path[i], digest)
        } else {
            (digest, path[i])
        };
        digest = hash_pair(left, right);
    }

    assert(digest == root);
}

