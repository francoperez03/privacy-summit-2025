# Stage 2 After: Hardened Merkle Membership Circuit

This circuit demonstrates fixes for **3 common ZK vulnerabilities** in Merkle tree membership proofs.

## 🎯 Educational Goal

Show how to secure a basic Merkle proof circuit against:

1. **Missing binding**: Proof reuse by different users
2. **Cross-app reuse**: Proof valid in one app used in another
3. **Replay attack**: Same proof used multiple times

---

## 🔒 The 3 Vulnerabilities & Fixes

### 1. Missing Binding Attack

**Problem**: Alice generates a proof. Bob intercepts it and uses it as his own.

**Why it happens**: The proof isn't tied to a specific user identity.

**Fix**: Include `account_id` as a **public input** and in the **leaf hash**:

```noir
account_id: pub Field,  // Public: binds proof to specific user

let leaf = make_leaf(account_id, attr, app_id);  // account_id in leaf
```

**Test**: See `test_attack_wrong_account_id()` - proof fails if account_id changes.

---

### 2. Cross-App Reuse Attack

**Problem**: Alice generates a proof for App A. She reuses it in App B (or on a fork).

**Why it happens**: No domain separation between applications.

**Fix**: Include `app_id` in the **leaf hash**:

```noir
app_id: pub Field,  // Public: identifies the app

let leaf = make_leaf(account_id, attr, app_id);  // app_id in leaf
```

**Test**: See `test_attack_cross_app_reuse()` - proof fails if app_id changes.

---

### 3. Replay Attack

**Problem**: Alice uses the same proof multiple times to claim benefits repeatedly.

**Why it happens**: No mechanism to mark a proof as "consumed".

**Fix**: Use a **nullifier** that binds the proof to a specific request:

```noir
request_id: pub Field,   // Public: identifies specific request
nullifier: pub Field,    // Public: unique per request

let nullifier = calc_nullifier(nsk, leaf, request_id);
assert(nf_calc == nullifier);
```

**Verifier responsibility**: Track seen nullifiers and **reject duplicates**.

**Test**: See `test_attack_replay()` - proof fails if request_id changes but nullifier stays the same.

---

## 🧪 Running Tests

```bash
nargo test
```

**Tests:**
- ✅ `test_valid_proof` - Valid proof passes
- ❌ `test_attack_wrong_account_id` - Fails if account_id changes
- ❌ `test_attack_cross_app_reuse` - Fails if app_id changes
- ❌ `test_attack_replay` - Fails if request_id changes
- ✅ `test_different_requests_generate_different_nullifiers` - Same user can make multiple valid proofs

---

## 📊 Summary Table

| Vulnerability | What attacker does | How we prevent it |
|--------------|-------------------|-------------------|
| **Missing binding** | Bob uses Alice's proof | Include `account_id` as public input and in leaf hash |
| **Cross-app reuse** | Use App A proof in App B | Include `app_id` in leaf hash for domain separation |
| **Replay attack** | Reuse same proof multiple times | Use nullifier tied to `request_id` + verifier tracks seen nullifiers |

---

## 🔑 Key Takeaways

1. **Public inputs matter**: They create binding between proof and context
2. **Domain separation**: Always include app/context identifiers in leaf hash
3. **Nullifiers**: Essential for "consume-once" semantics
4. **Verifier responsibility**: Circuit + off-chain checks work together (e.g., tracking nullifiers)

---

## 📚 Comparison with Stage 2 (Vulnerable)

See [../stage_2/src/main.nr](../stage_2/src/main.nr) for the vulnerable version that accepts:
- `leaf` as a raw `Field` (no binding to user)
- No `app_id` (no domain separation)
- No nullifier mechanism (allows replay)
