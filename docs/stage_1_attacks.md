# Cheating Attempts and Protections in the ZK Circuit (Stage 1)

This document outlines various strategies an attacker might use to cheat the circuit and how the current design blocks each of them.

---

## 1) Change DOB at proof time (Prove-time farming)
**Attacker's idea:** “I’ll try an older date of birth so I pass the age check.”

**Where it fails:**
```rust
assert(dob_commit_calc == dob_commitment);
```
The circuit recalculates `H(dob)` and requires it to match the committed value.
Changing `dob` breaks the hash and the proof fails.

✅ Blocks **prove-time commitment farming**.

---

## 2) Replay the same proof in another request or app
**Attacker's idea:** “I’ll reuse this valid proof for a different request or even a different app.”

**Where it fails:**
```rust
let nullifier_calc = H(nsk, dob_commitment, app_silo, request_id);
assert(nullifier_calc == nullifier);
```
Changing `request_id` or `app_silo` → changes the derived `nullifier` → old proof doesn’t match.

Even if the attacker tries to forge a new nullifier, they would need `nsk`, which they don’t have.

✅ Blocks **replay across requests** and **cross-app reuse**.

---

## 3) Reuse proof within the same context (double use)
**Attacker's idea:** “I’ll submit the same proof twice for the same request.”

**Where it fails:**
- Off-chain, the verifier keeps a set of seen `nullifiers`.
- Second use → same `nullifier` → immediately rejected.

The circuit proves how the nullifier was generated; the verifier enforces uniqueness.

✅ Blocks **intra-request replay**.

---

## 4) Forge a nullifier that is marked as unused
**Attacker's idea:** “I’ll generate a nullifier that the system thinks is still unused.”

**Where it fails:**
- `nullifier` is derived from `nsk`, `dob_commitment`, `app_silo`, and `request_id`.
- Without the secret `nsk`, the attacker cannot compute a valid nullifier.
- Changing `dob_commitment` would break the first commitment check.

✅ Blocks **targeted nullifier forgery**.

---

## 5) Tamper with `cutoff` (business rule bypass)
**Attacker's idea:** “I’ll use a higher `cutoff` to pass the age check.”

**Where it fails:**
```rust
assert(dob_f <= cutoff_f);
```
The verifier sets `cutoff` and sends it as a public input.
If the prover alters it, the verifier will detect the inconsistency.

✅ `cutoff` is part of the challenge from the verifier. **Blocks age threshold bypass**.

---

## 6) Pre-commitment farming
**Attacker's idea:** “I’ll precompute and register multiple `H(dob)` values and pick the one that works.”

**Where it fails:**
- It doesn’t break in the circuit directly.
- External policy: the verifier ensures that only **one `dob_commitment` is active per account**.
- Updating one revokes the others.

✅ Prevented by **account policy**, not circuit logic.

---

## 7) Brute-force `dob_commitment` (by third parties)
**Attacker's idea:** “I’ll guess all possible DOBs and match the commitment hash.”

**Where it fails:**
- **It doesn’t fail currently** if no salt is used.
- To block this, use a salt: `H(dob, salt)`.

This does not affect replay/farming prevention, but **enhances privacy**.

✅ Optionally add **salt** to prevent brute-force attacks.

---

### Summary
| Threat                          | Blocked by                      |
|---------------------------------|----------------------------------|
| Change DOB to pass             | `assert dob_commit == H(dob)`    |
| Replay in other context        | Nullifier includes context       |
| Reuse proof in same context    | Off-chain nullifier tracking     |
| Forge valid nullifier          | Depends on secret `nsk`          |
| Tamper with cutoff             | Verifier defines public input    |
| Precommitment farming          | External account policy          |
| Brute-force `dob_commitment`   | Add salt (optional)              |

