# SILTU – Programmable Privacy Framework (Refined)
*A compact, product‑first method to design correct ZK proofs and circuits.*

SILTU guides a team from **intent** to **verifiable design**. Each letter is a checkpoint. Keep it implementation‑agnostic (applies to Noir, Circom, gnark, Halo2, etc.).

---

## S — Statement (natural language)
**Question:** *What do we need to prove, exactly, and at which moment of the business flow?*

- One clear, human sentence that captures the verifier’s need.
- Includes the **business context** (where in the flow the proof is consumed).
- Defines **accept / reject** criteria in words; excludes what is out of scope.

**Deliverable:** a single sentence + acceptance criteria bullets.

---

## I — Inputs (public vs private)
**Question:** *Which data are private witnesses and which must be public or anchored — and who is the authority for each one?*

Specify for every datum:
- **Private (witness):** exact fields the prover keeps secret.
- **Public / Anchored:** values the verifier must see or that are bound to an external state (roots, epochs, signatures, policies).
- **Source of truth:** on‑chain contract, backend, signed snapshot, file, oracle.
- **Authority & cadence:** who publishes/updates, and how often.
- **Transport & retention:** how the prover gets it; how long it remains valid.

**Deliverable:** an input matrix listing *name · role (private/public) · source · authority · update policy*.

---

## L — Logic (formal predicate)
**Question:** *What is the minimal boolean predicate the circuit must satisfy?*

- Write a **precise predicate**: \`f(witness, public) = true\`.
- List the exact **cryptographic relations** (hash/commitment equality, Merkle inclusion, signature checks), **arithmetic relations** (conservation, comparisons, ranges), and any **binding tags**.
- No business prose here; only conditions that the circuit will enforce.
- Deterministic, unambiguous, minimal.

**Deliverable:** formal statement + enumerated constraints the prover must satisfy.

---

## T — Traps (adversary model & defenses)
**Question:** *How could someone cheat, and how do we prevent it?*

Model likely attacks and pair each with a defense primitive.

**Common threat families**
- **Replay / context drift.**  
- **Commitment farming / prove‑time swapping.**  
- **Double‑spend / uniqueness.**  
- **Value inflation / conservation breaks.**  
- **Membership forgery (Merkle / set).**  
- **Range / overflow / underflow.**  
- **Ownership / authority binding.**  
- **Freshness / epoch / revocation.**  
- **Privacy leakage / linkability.**

**Defense primitives**
- Commitment checks (`H(secret) == commit`).
- **Nullifiers** with **context binding** (domain separation via tags: app, function, chain, epoch, request).
- Merkle inclusion / accumulator membership.
- Balance conservation and invariants.
- **Range proofs / checks** for bounded values.
- Domain‑separated hashes / typed tags.
- Signatures / MACs from authorities.
- Salts and high‑entropy randomness.
- Freshness windows, expirations, revocation lists.

**Deliverable:** threat → control table, stating what is enforced in‑circuit vs. policy/verifier side.

---

## U — Unit tests (evidence)
**Question:** *How do we demonstrate the circuit does exactly what S and L specify?*

Cover at least:
- **Positive cases** matching the intended flow.
- **Negative cases per trap** (each listed threat must fail). 
- **Edge cases** (boundary values, selector flips, root ±1, equality at threshold, zero values).
- **Determinism & binding** (changing context or commitments must fail).
- **Migration / lifecycle** tests if there are versions, epochs, or key rotations.

**Deliverable:** a test suite with clear names: `test_valid_*`, `test_fails_*_<trap>`.

---

## SILTU artifacts (what you should produce)
- **S**: `statement.md` — natural‑language claim + acceptance criteria.
- **I**: `inputs.yaml` — matrix of witnesses and public/anchored data with authorities.
- **L**: `logic.md` — formal predicate and constraint list (optionally a DSL snippet).
- **T**: `threat_matrix.md` — threats ↔ controls (in‑circuit / verifier / policy).
- **U**: `tests/` — positive, negative, edge, lifecycle.

Together, these artifacts become the contract between product, cryptography, and engineering. SILTU keeps the language shared: **natural in S, formal in L, enforceable in code, verifiable in tests**.

