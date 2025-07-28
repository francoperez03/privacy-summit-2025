# The Path to Designing Awesome ZK Circuits

A practical workshop on building correct and meaningful Zero-Knowledge proofs.

## 📋 What is this?

This workshop is designed to help developers and product teams think clearly when designing Zero-Knowledge (ZK) circuits.

Instead of jumping straight into code, we guide you through a step-by-step framework that aligns real-world business logic with cryptographic proofs.

You’ll learn:

- How to identify what you're *really* trying to prove
- How to design a circuit with meaningful public/private inputs
- How to prevent common mistakes like invalid proofs, replay attacks, or ambiguous statements
- How to test and validate circuits early

> The goal: ZK circuits that are correct, useful, and trustworthy.

## 📂 What's inside

- [`/circuits`](./circuits): All the circuits used in the workshop (written in Noir)
  - `stage_1/`: Proving you're over 18
  - `stage_1_after/`: Hardened with nullifier and context
  - `stage_2/`: Merkle inclusion
  - `stage_2_after/`: Structured leaf and binding
  - `stage_3/`: Minimal UTXO flow
  - `stage_3_after/`: Hardened UTXO with traps and context

- [`/docs`](./docs): Full writeups and framework files
  - `framework.md`: The SILTU design framework
  - `next_steps.md`: Pro-level checklist (P1–P5)
  - `stage_1_attacks.md`: Threats and defenses for age proof
  - `stage_2_attacks.md`: Threats and defenses for membership
  - `stage_3_attacks.md`: Threats and defenses for UTXO

- `README.md`: You are here.

## 🎥 Presentation

Slides from the session:  
👉 [View the slides](https://example.com/zk-workshop-slides.pdf)

## 🛠 Tech stack

- [Noir](https://noir-lang.org)
- ZK circuit design principles
- Zero-knowledge application patterns

## 🙌 Who is this for?

- **Product teams** who want to use ZK but don’t know where to start  
- **Developers** building circuits that need to prove meaningful things  
- **Researchers** designing UX-integrated cryptographic flows

---

📣 Questions or ideas? Reach out:  
- [@wakeuplabs](https://x.com/wakeuplabs)  
- [@crypto_dev_1](https://x.com/crypto_dev_1)

