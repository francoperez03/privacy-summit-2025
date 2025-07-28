# Next steps after SILTU (P1–P5)

SILTU gets you to a **correct, minimal circuit**. To ship a production‑grade feature, harden it with the five Pro pillars. Keep this doc short, action‑oriented, and attach it to PRs/design reviews.

---

## P1 — Threat model & trust assumptions
**Goal:** Make explicit who can attack, what they can do, and which components you trust.

**Answer:**
- Actors & capabilities (e.g., replay, front‑run, censorship, oracle tampering).
- Trusted elements: setup, on‑chain contract, timestamp/epoch source, relayer, key store.
- Out‑of‑scope risks (what this circuit does *not* defend against).

**Deliverables:** `p1_threat_model.md` with a table *actor → capability → control / out‑of‑scope*.

---

## P2 — Context binding (domain separation)
**Goal:** Ensure a valid proof cannot be reused in a different place or time.

**Answer:**
- Which identifiers define the context? *(app/contract/function, chainId, version, epoch, request_id).*  
- How are they bound? *(domain tags in hashes, input publics, salt structure).*  
- What happens if any of them changes? *(proof must become invalid).*

**Deliverables:** list of binding fields and exact formulas, e.g.  
`nullifier = H(TAG, nsk, leaf, app_silo, epoch_id, request_id)`.

---

## P3 — Lifecycle, expiry & governance
**Goal:** Plan how proofs, roots, keys and policies **change safely over time**.

**Answer:**
- What expires? *(roots, epochs, proofs, allowlists, keys, versions).*  
- How to revoke/rotate/migrate? *(process, authority, backward compatibility).*  
- Who signs or authorizes updates? *(DAO, multisig, ops runbook).*

**Deliverables:** lifecycle diagram + `governance.md` with roles and procedures.

---

## P4 — Budgets & performance
**Goal:** Fit within concrete limits and know who pays each cost.

**Answer:**
- Limits: constraints/gates, proof size, proving time, verification gas/CPU, latency SLO.
- Techniques: recursion/aggregation, precomputation, off‑chain proving, batching.
- Economics: payer per step *(user, relayer, protocol, sponsor)*.

**Deliverables:** `budgets.md` with target numbers and the technique plan; a perf checklist for CI.

---

## P5 — Integration without leaks
**Goal:** Verify, log and operate the system **without exposing secrets**.

**Answer:**
- Where is the proof verified? *(on‑chain, L2, backend service).*  
- What is persisted/logged/telemetried? *(ensure no private fields, only nullifiers/roots/epochs).*  
- How do components communicate? *(encryption, signatures, attestation, retries).*
- Operational safeguards: rate limits, DoS protection, nullifier seen‑set, monitoring & alerts.

**Deliverables:** integration diagram, `privacy_ops.md` with logging redaction rules and runbooks.

---

## Checklist (paste in PRs)
- [ ] **P1** Threat model reviewed; out‑of‑scope documented.  
- [ ] **P2** Binding fields fixed; replay across context impossible.  
- [ ] **P3** Expiry/rotation procedures defined and tested.  
- [ ] **P4** Budgets met; CI perf checks green; payer model clear.  
- [ ] **P5** Verification and observability audited for leaks.

> Ship confidently: SILTU makes it **correct**, P1–P5 makes it **robust**.

