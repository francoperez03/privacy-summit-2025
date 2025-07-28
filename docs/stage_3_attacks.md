# Cheating Attempts and Protections in the ZK Circuit (Stage 3 — Minimal UTXO)

This document lists plausible attacks against the **minimal UTXO circuit** and how the current design mitigates (or explicitly does **not** mitigate) each one.

**What the minimal circuit proves:**

1. **Input membership**: the spent note `leaf = C(owner_pk, value, rho)` is in `root`.
2. **Value conservation**: `value == value_1 + value_2`.
3. **Well‑formed outputs**: `commit1 = C(owner_pk_1, value_1, rho_1)` and `commit2 = C(owner_pk_2, value_2, rho_2)`.

**What it does not prove (by design, in this stage):**

- No **nullifier** (so no double‑spend prevention).
- No **state transition** to a new root.
- No **context binding** (chain/app/epoch).
- No **range checks** on values.
- No **fees** or asset IDs.
- Single input note, two outputs only.

---

## 1) Double‑spend the same input note

**Attacker’s idea:** “I’ll reuse the same membership proof to spend the note again.”

**Where it fails (current stage):**\
It **doesn’t** fail in the circuit. There is **no nullifier** or state update to mark the note as spent.

**Mitigation (next stage):**

- Add a **public nullifier** derived from a secret key and the input note commitment:
  ```
  nullifier = H(nsk, leaf, app_silo, epoch_id, request_id)
  ```
- The verifier keeps a **set of seen nullifiers** and rejects duplicates.
- Optionally prove transition to a **new root** that removes the input and inserts the outputs.

✅ **Status in minimal:** **Not prevented**. Must be handled in hardened version.

---

## 2) Inflate value (create money from nothing)

**Attacker’s idea:** “I’ll make `value_1 + value_2` greater than the input value.”

**Where it fails:**

```rust
assert(value == (value_1 + value_2));
```

The conservation check blocks any mismatch.

✅ Blocks **value inflation**.

---

## 3) Use a forged root or unrelated tree

**Attacker’s idea:** “I’ll choose a root where my fake leaf is included.”

**Where it fails:**

```rust
assert(calc_root == root);
```

The circuit recomputes the root from the provided path.\
However, the circuit **cannot know** if `root` is *authorized/current*.

**Mitigation:**

- The verifier must supply/trust only a **current, authorized root** (on‑chain commitment, signed snapshot, epoch‑tagged).

✅ Prevented by **verifier policy**, not circuit logic.

---

## 4) Swap output commitments after proving

**Attacker’s idea:** “I’ll present different `commit1/commit2` than the ones the circuit expects.”

**Where it fails:**

```rust
assert(c1 == commit1);
assert(c2 == commit2);
```

The circuit recomputes commitments from private outputs and compares against the public `commit1`/`commit2`.

✅ Blocks **commitment tampering**.

---

## 5) Reuse the proof in a different app/epoch (replay across contexts)

**Attacker’s idea:** “I’ll take the same proof and use it in another environment.”

**Where it fails (current stage):**\
There is **no context binding**. If another verifier accepts the same `root` and `commit*`, the proof could be replayed.

**Mitigation:**

- Bind proof to a **context** using public values (e.g., `app_silo`, `epoch_id`, `request_id`) and include them in the nullifier (next stage).
- Alternatively, include a **domain tag** in the note commitment or root binding.

✅ **Status in minimal:** **Not prevented**. Needs **binding** in hardened version.

---

## 6) Negative or oversized values / overflow

**Attacker’s idea:** “I’ll use out‑of‑range values to bypass logic.”

**Where it fails (current stage):**\
No explicit **range checks** are enforced. Depending on the field arithmetic, extreme values could wrap.

**Mitigation:**

- Add **range checks**: `0 ≤ value, value_1, value_2 ≤ MAX`.
- Use typed unsigned integers where appropriate or explicit constraints ensuring bounds.

✅ **Status in minimal:** **Not prevented**. Add **range checks** in hardened version.

---

## 7) Linkability of outputs (privacy leakage)

**Attacker’s idea:** “I’ll correlate outputs by observing identical commitments or repeated randomness.”

**Where it fails (current stage):**\
If `rho_1` or `rho_2` are reused or predictable, commitments may be linkable.

**Mitigation:**

- Ensure \*\*fresh, high‑entropy \*\*\`\` for every note.
- Consider adding **domain tags** to commitments (e.g., `"NOTE"`).

✅ **Status in minimal:** Relies on **good randomness**. Harden with domain separation.

---

## 8) Wrong path direction (left/right manipulation)

**Attacker’s idea:** “I’ll tweak the selector to force a path to match.”

**Where it fails:**

- Any wrong `selector` or sibling in `path` will produce a different `calc_root`, failing:
  ```rust
  assert(calc_root == root);
  ```

✅ Blocks **path manipulation**.

---

## 9) Replace receiver or change outputs after verification

**Attacker’s idea:** “I’ll modify `owner_pk_1` or `value_1` after generating the commitments.”

**Where it fails:**

- Commitments are checked against public `commit1/2`. Any change breaks:
  ```rust
  assert(c1 == commit1);
  assert(c2 == commit2);
  ```

✅ Blocks **post‑proof output tampering**.

---

### Summary

| Threat                              | Blocked by / Status                                       |
| ----------------------------------- | --------------------------------------------------------- |
| Double‑spend the same input         | ❌ Not blocked. Add **nullifier** + seen‑set (hardened).   |
| Value inflation                     | ✅ `assert(value == value_1 + value_2)`                    |
| Forged / unauthorized root          | ⚠ Verifier must enforce **authorized current root**.      |
| Swap public commitments             | ✅ Recompute and compare commitments                       |
| Cross‑context replay                | ❌ Add **context binding** (app/epoch/request) + nullifier |
| Out‑of‑range / overflow             | ❌ Add **range checks**                                    |
| Output linkability                  | ⚠ Use **fresh randomness (**\`\`**)** + domain tags       |
| Path/selector manipulation          | ✅ Root recomputation mismatch                             |
| Replace receiver/outputs post‑proof | ✅ Commitment equality checks                              |

---

### Next steps to harden

1. **Nullifier & seen‑set** to prevent double‑spend.
2. **Context binding** (`app_silo`, `epoch_id`, `request_id`) in nullifier.
3. **Range checks** on values.
4. **Authorized root** (on‑chain/signed/epoch).
5. **Fresh randomness** and **domain separation** in commitments.
6. **State transition proof** (optional): prove the **new root** with outputs inserted and input removed.

