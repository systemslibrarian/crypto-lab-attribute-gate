# Attribute Gate

**Encrypt to a policy instead of to a person, test collusion resistance, split issuance across independent authorities, and see what an honest revocation overlay must still do.**

[Live demo](https://systemslibrarian.github.io/crypto-lab-attribute-gate/) · one of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.

---

## What It Is

Four deliberately separate browser lessons run over real **BLS12-381** pairings. Exhibits 1–8 implement **FAME** — *Fast Attribute-based Message Encryption*, Shashank Agrawal and Melissa Chase, **ACM CCS 2017** ([ePrint 2017/807](https://eprint.iacr.org/2017/807)) — as public-policy ciphertext-policy attribute-based encryption. Exhibit 9 implements the CP-A2BE construction from **FABESA** — Long Meng, Liqun Chen, Yangguang Tian and Mark Manulis, **ACM CCS 2024** ([ePrint 2024/986](https://eprint.iacr.org/2024/986)) — as a bounded, partially hidden-policy lesson. Exhibit 10 independently implements the decentralized multi-authority CP-ABE construction of Yannis Rouselakis and Brent Waters, **Financial Cryptography 2015** ([paper](https://y.rouselakis.com/papers/2015-016.pdf); [authors' asymmetric Charm implementation](https://jhuisi.github.io/charm/_modules/abenc_maabe_rw15.html)). Exhibit 11 is an application-layer epoch-gating and owner-assisted DEK-rewrap adaptation built around FAME; it is not part of RW15 and is not presented as a new revocable-ABE construction.

Ordinary public-key encryption addresses a *person*. Ciphertext-policy ABE addresses a *rule*: you encrypt under `(Doctor AND Cardiology) OR Emergency`, and whoever turns out to hold a satisfying set of attributes can decrypt. Nobody has to know in advance who that will be.

The security property that makes it more than a filing convention is **collusion resistance**: two people whose attributes only *jointly* satisfy the policy must not be able to pool their key material. Every ABE paper states this. This demo makes you do it — it splices two real keys into one, runs the genuine decryption on the result, and shows the exact term that refuses to cancel.

FABESA addresses a different question. Its partially hidden payload withholds attribute **values**, but deliberately publishes attribute names, the matrix, row map, structure, dimensions and lengths. The page compares two equal-public-payload worlds, performs the paper's candidate decryptions, and uses an AES-GCM tag—not an expected plaintext—as the bounded teaching wrapper's success oracle.

RW15 addresses the single-authority escrow boundary. `Doctor@Hospital` and `Cardiology@Board` are issued under independent master secrets, yet components for the same canonical global identifier combine. Components for two different identifiers can satisfy the public labels while recovering the wrong `GT` element; the record tag then rejects. Compromising one authority lets the adversary mint that authority's attributes for any identifier, but it does not mint the other authority's namespace.

The epoch lesson addresses a different lifecycle problem. A fresh epoch attribute is required in every new policy, a complete current-epoch FAME key is withheld from a revoked holder, and an owner who can recover the DEK replaces selected access headers without rewriting payload bytes. Saved old keys and headers still open saved old data, and replay is stopped only when a separately trusted checkpoint rejects the old header.

### The exact primitives

| Layer | Primitive | Source |
|---|---|---|
| Public-policy ABE | FAME CP-ABE, linear-assumption parameter k = 2 | Agrawal & Chase, CCS 2017, Figure 3.1 |
| Hidden-value ABE | FABESA CP-A2BE, bounded one-value-per-name profile | Meng et al., CCS 2024, Figure 5 and §3.3 |
| Multi-authority ABE | RW15 large-universe decentralized CP-ABE | Rouselakis & Waters, FC 2015, §4.1 |
| Pairing | BLS12-381, Type-3: `e : G1 × G2 → GT` | `@noble/curves` v2 |
| Random oracles | Scheme-specific, versioned DSTs into `G1` for FAME/FABESA and into `G2` for RW15 | RFC 9380 |
| KDF | HKDF-SHA-256 | RFC 5869, via WebCrypto |
| AEAD | AES-256-GCM, 96-bit nonce, 128-bit tag | NIST SP 800-38D, via WebCrypto |

Setup, KeyGen, Encrypt and Decrypt for FAME, FABESA and RW15 are hand-written from their papers so they stay inspectable, along with the modular inverse, construction-specific access-tree → LSSS conversions, reconstruction and bounded FABESA candidate enumeration. Only the field/curve arithmetic and hash-to-curve are library code. The epoch lesson composes real FAME, HKDF and AES-GCM operations but makes no theorem claim for that composition.

### Why FAME, and not the BSW07 scheme everybody cites

Bethencourt, Sahai and Waters (**IEEE S&P 2007**) is the access-tree construction most ABE explanations use, and it is cited here for exactly what it is: the origin of the access-tree formulation and of the collusion argument, **in the symmetric-pairing setting it actually describes**, `e : G0 × G0 → GT`.

BLS12-381 is Type-3 — `e : G1 × G2 → GT`, with no efficient isomorphism in either direction. Several BSW elements are required on both the key side and the ciphertext side, which is precisely where the symmetric assumption is load bearing, so transplanting BSW onto this curve and still calling it BSW07 would be a spec-fidelity claim the code could not support. FAME was designed for Type-3 from the start, is efficient, is large-universe, and removes the translation burden entirely. The collusion property is identical in both schemes — per-user key randomization is what blocks pooling either way — so nothing pedagogical is lost.

A documented Type-3 translation of BSW07 was considered and rejected: viable, but it obliges a proof of which elements land in `G1` versus `G2`, which are published in both, and why the duplication does not break the security argument — for no pedagogical gain over FAME.

Every group element the page prints is tagged `G1`, `G2`, `GT` or `Zp`. That typing is not decoration; it is the discipline that keeps the Type-3 distinction visible.

### Security model, in one paragraph

FAME is proved **fully secure** under a variant of the *k*-linear assumption in the **random oracle model**. It is single-authority: the master secret can mint a key for any attribute set, so **the authority can decrypt everything** (exhibit 6). It provides **no revocation** (exhibit 7). It carries a **one-use restriction** — the MSP row-labelling map must be injective — worked around here by indexed attribute copies, at a cost of a factor of *k* in key size (exhibit 2).

FABESA Theorem 4 proves adaptive anonymity in the random-oracle model under the DLIN assumption, using the paper's asymmetric Type-III formulation in both `G1` and `G2`. Its challenge policies must expose the same public payload, its challenge messages must be equal-size, and every queried key must satisfy neither challenge policy. This lab's canonical encodings, finite candidate search and HKDF/AES-GCM record wrapper are teaching adaptations; the page does **not** transfer Theorem 4 to that composition.

RW15 proves static, non-adaptive security in the random-oracle model under the paper's `q`-DPBDHE2 assumption, for a challenge matrix within the theorem's `q × q` bound. Its game permits statically declared corrupted authorities subject to the challenge-set restriction. The implementation follows the authors' asymmetric placement (`H(GID), F(attribute) ∈ G2`) over BLS12-381, but its canonical encodings and hybrid record wrapper are this lab's profile, not Charm wire compatibility. The executable compromise fixture is narrower than the theorem's game: it exposes one honestly generated authority secret, not rogue-key registration, malformed or equivocal issuance, adaptive corruption or directory compromise. RW15 supplies neither revocation nor policy hiding, sender authentication, authority-directory authentication, GID proofing, CCA security, adaptive security or a standard-model proof.

**This is not production cryptography.** It is a teaching demo. Every key is generated in the browser tab, lives in memory only, and is discarded when the tab closes. Nothing is constant-time and no side-channel resistance is claimed.

---

## Exhibits

1. **Compose a policy and seal a record under it.** Build an access tree from k-of-n gates (OR is 1-of-n, AND is n-of-n), then encapsulate under it. A disclosure draws the boundary the demo refuses to blur: FAME's message space is *one element of GT*, so the record is not ABE-encrypted. A random `GT` element is encapsulated under the policy, HKDF-SHA-256 turns it into a 256-bit AES key, and AES-256-GCM seals the record with the policy string as associated data. This is the pipeline the FAME paper itself recommends, and the same KEM/KDF/AEAD shape as **HPKE Envelope**.

2. **The tree becomes a matrix.** FAME never sees your tree — it sees a matrix `M` and a row-labelling map `π`, and a key opens the ciphertext exactly when the rows it owns combine to `(1, 0, …, 0)`. This exhibit shows the conversion, column by column, and the **one-use restriction**: if `Doctor` appears in two rows, `π` is not injective and the scheme breaks. The workaround is indexed copies — `Doctor:1`, `Doctor:2` — applied on **both** sides, so a holder of `Doctor` must carry every copy. The key-size cost is displayed as a count, not asserted.

3. **Issue keys and try to open the record.** Alice `{Doctor, Cardiology}`, Bob `{Doctor}`, Carol `{Emergency}`, Dan `{Nurse}`, Eve `{Cardiology}`. Every refusal names its cause and highlights the unsatisfied gate in the tree and the missing rows in the matrix.

4. **Threshold gates and the Lagrange step.** Switch a gate to "2 of 3" and the reconstruction stops being a sum of ones. The interpolation is shown gate by gate — coefficients rendered as the small rationals they are, `3/2` rather than a 77-digit modular inverse — and the combination `Σ γᵢ Mᵢ` is then recomputed from the matrix rows on screen rather than inferred from the fact that decryption worked.

5. **Collusion — the climax.** Bob `{Doctor}` and Eve `{Cardiology}` pool their keys against `Doctor AND Cardiology`. Six steps: neither can open it alone; the keys are spliced into one object of the same type the decryptor takes; **the policy check passes**; the blinding fails to cancel; the leftover factor is computed twice by two independent routes and compared byte for byte; the record stays shut. The per-row ledger prints `Br_base − Br_owner` for `ℓ = 1, 2, 3` — zero on rows from the key that supplied `sk0`, non-zero on borrowed rows. Both splice directions are tried.

6. **The authority can read everything.** Shown as two separate steps, because collapsing them teaches the right conclusion by the wrong route: `msk` is *not* a decryption key, and there is no function taking `msk` and a ciphertext to a plaintext. What `msk` grants is KeyGen for an arbitrary attribute set — so the authority mints itself a satisfying key, and *then* decrypts with it like anyone else.

7. **There is no revocation.** Revoke a holder, seal a brand-new record afterwards, and watch the revoked key open it. Revocation here is a boolean on a staff list; the key, the public key and every ciphertext are untouched.

8. **Failure codes.** `POLICY_UNSATISFIED` · `ATTR_MISSING` · `THRESHOLD_NOT_MET` · `COLLUSION_BLOCKED` · `MALFORMED_POLICY` · `ATTRIBUTE_REUSED`. Every original FAME verdict prints its identifier verbatim. `ATTRIBUTE_REUSED` is an *internal invariant*, never a user-facing verdict: with the indexed-copy transform in place a duplicate row label cannot reach the scheme, so it is an assertion — if it ever fires, the transform is broken.

9. **Hide attribute values—and inventory what remains public.** Two FABESA ciphertexts use different sensitive values behind the same three names, Boolean structure, `3 × 2` MSP and serialized-size profile. The observer sees that public payload, group elements, nonce, context and lengths but not the values or plaintext. A key with two publicly plausible reconstruction candidates rejects the wrong hidden-value branch and authenticates the right one; wrong values, foreign-authority components and the sealed-record bit flip share a generic failure. The lesson also refuses an over-32-candidate fixture before cryptographic trials and keeps the paper theorem separate from the bounded hybrid adaptation.

10. **Issue attributes independently with RW15.** Hospital and Board run separate authority setups. Their components for one byte-exact GID open an `AND` policy; a raw adversarial decryption that selects one row from each of two different GIDs satisfies the labels but fails cryptographically. A compromised Hospital authority opens a Hospital-only policy yet cannot manufacture Board's component for the two-authority policy. The repeated-attribute fixture also shows the difference from FAME: RW15 reuses one logical `STUDENT@UT` key across two rows instead of inventing occurrence suffixes.

11. **Advance an epoch, then account for modeled update work and retained copies.** Bob's old key still opens the epoch-1 snapshot after revocation. Alice receives a complete epoch-2 key and opens the current header; Bob does not. Owner-assisted rewrap replaces the FAME capsule and wrapped DEK while the AES-GCM payload remains byte-for-byte unchanged. A saved old header still works without external freshness state, while the current trusted checkpoint detects that rollback. The panel reports actual key generations, header encryptions, owner unwraps, DEK wraps, payload encryptions and bytes rewritten.

---

## When to Use It

Use attribute-based encryption when the set of people who should read something is defined by a **rule** you can state in advance but a **membership** you cannot: shared medical records, classified archives with clearance lattices, multi-tenant data where access follows job function rather than identity.

Use a policy-hiding construction only after stating which parts of the policy must be hidden. This FABESA profile is useful when values such as a department or clearance are sensitive but their category names and access structure may remain public; it is not suitable when names, structure, dimensions, traffic shape or outcomes must also be concealed.

Use decentralized multi-authority ABE when independently controlled issuers must contribute attributes to one access decision. RW15 removes a central master issuer, not trust: authenticated authority keys, namespace control and proof that every issuer is binding the same real subject to the same GID remain deployment responsibilities.

Use the epoch lesson to reason about the concrete work a bounded application-layer revocation overlay performs. It is appropriate for comparing future-data protection, selected-record header rewrap, retained snapshots, freshness state and escrow; it is not a production revocation design.

**Do NOT use it** when any of these is true:

- **You need scalable or public ciphertext update.** FAME and RW15 have no native revocation. The bounded epoch adaptation requires full-key reissue and owner-secret access to each selected record's DEK; it is not public or server-only update.
- **You cannot accept issuer or owner escrow.** FAME's authority reads everything. RW15 divides issuance, but each authority can still mint its own namespace for any GID, and a policy depending only on a compromised authority falls. The epoch adaptation adds an owner capability that can recover every modeled DEK.
- **You are reaching for a library, not a lab.** Use a reviewed implementation (`OpenABE`, `charm-crypto`) and a reviewed pairing library. This code is written to be read, not deployed.
- **The rule is really an identity.** If you know who the recipient is, ordinary public-key encryption or HPKE is simpler and stronger.

---

## Live Demo

<https://systemslibrarian.github.io/crypto-lab-attribute-gate/>

You can: build any monotone access tree from the attribute universe or type your own attribute; seal a record; issue and re-issue keys; try to open the record as any holder; switch a gate to a threshold and watch the Lagrange reconstruction; pool any two keys and inspect the term that refuses to cancel; mint an authority key; revoke someone and watch it change nothing; compare two equal-shape FABESA ciphertext worlds; combine independently issued RW15 components for one GID and try a raw cross-GID pool; compromise one issuer; then advance an epoch, rewrap a DEK, test saved snapshots and measure the update work.

---

## What Can Go Wrong

The threat model this lab makes concrete, and the failure modes an implementer meets.

**The authority reads everything (exhibit 6).** Inherent to single-authority ABE, exactly as it is to identity-based encryption — the same escrow property **IBE Gate** teaches, now over policies rather than identities. Mitigation is architectural: multi-authority ABE, threshold key issuance, or not centralising the authority in the first place.

**No revocation (exhibit 7).** An issued key decrypts matching ciphertexts indefinitely. Removing access requires re-encryption or a scheme built with revocation. A deployment that treats an ABE key like a session token will be wrong about who can read its archive.

**The one-use restriction will bite on the first realistic policy.** `(Doctor AND Cardiology) OR (Doctor AND Emergency)` uses `Doctor` twice, and FAME requires `π` to be injective. The indexed-copy workaround is not policy-side only: if `Doctor` becomes `Doctor:1 … Doctor:k`, every key entitled to `Doctor` must carry all `k` copies, because issuance cannot know which row index a future policy will use. A policy-side-only implementation simply fails at issuance, and the key-size cost is real — the paper states the factor of `k` explicitly.

**Attribute reuse without indexing is a security failure, not an inconvenience.** If two rows carry the same label, the scheme's own security argument breaks (the reduction needs each masked row to be the only place its mask appears). Stripping the index before hashing — which the authors' reference implementation does, under a comment noting reuse is not allowed — restores the collision. Here the index is part of the hashed label, and `ATTRIBUTE_REUSED` asserts the invariant.

**Nothing detects collusion.** When a pooled key fails, no component of FAME noticed anything. Decryption ran to completion and returned a well-formed group element; it was simply the wrong one, and the AEAD tag is what refused. A system that expects an ABE library to *report* a collusion attempt is expecting something the primitive does not offer.

**FAME provides no policy privacy; FABESA here provides only partial policy hiding.** FAME's whole policy travels with its ciphertext. The separate FABESA lesson hides attribute values, not names, matrix, row map, Boolean structure, dimensions, serialized lengths, key attribute names, candidate counts or observed outcomes. Calling that “the policy is hidden” without the qualifier would be false.

**Candidate search is observable and bounded.** Matching public names can yield several possible reconstructions because their values are hidden. The wrapper tries them sequentially and uses authentication as its oracle, so work and success position can leak; it refuses above 32 candidates or 10 matched rows. It is not an oblivious search protocol.

**The FABESA wrapper is not the FABESA theorem.** Figure 5 encrypts one `GT` element. Canonical identifier encodings, HKDF, AES-GCM and the tag-based candidate oracle make the browser lesson executable, but no proof in this repository establishes adaptive anonymity for that composition. The GCM tag recognizes a candidate-derived key and protects data under that key; it does not authenticate a sender or ciphertext origin, and the lab makes no CCA-security claim. ABE encryption is public, so anyone can create a new envelope containing attacker-chosen content.

**A global identifier is cryptographic input, not identity proof.** RW15 hashes the byte-exact GID into each independently issued component, which is what defeats cross-user pooling. It does not define enrollment, canonicalize names across organizations or prove that two issuers checked the same person. This profile deliberately accepts only a narrow ASCII grammar rather than silently normalizing or case-folding identities.

**Independent authorities reduce one failure mode; they do not erase escrow.** Compromising Hospital lets an attacker mint every Hospital-controlled attribute for any GID. Policies that also require an honest Board attribute still depend on Board, while a Hospital-only policy is lost. The public-key directory and authority-to-namespace mapping must themselves be authenticated outside the construction.

**An epoch label alone is not revocation.** Enforcement requires withholding a complete new FAME key from the revoked holder, placing the new epoch in every new policy, rewrapping every old record that should move, and rejecting old headers against separately trusted freshness state. AES-GCM authenticates a header but does not make an authentic old header fresh.

**The issuer state is part of the trusted system.** The bounded model accepts a caller-supplied holder identifier and business attributes, checks exact identifiers against an application revocation set and advances an in-memory epoch. A deployment must authenticate stable subject identifiers and authoritative attributes, prevent aliases, protect epoch/revocation/checkpoint state against rollback and deliver keys securely. This lab implements none of that enrollment, state-protection, distribution or multi-device synchronization machinery.

**Owner-assisted rewrap is not revocable-storage ABE.** The adaptation decrypts an owner capsule to recover the DEK, makes a fresh FAME capsule and replaces the wrapped-DEK header. It has no public update token and no combined FAME/RW15/revocation proof. It is intentionally contrasted with revocable-storage ABE and self-updatable encryption, where public ciphertext evolution is a construction feature ([Sahai–Seyalioglu–Waters 2012](https://eprint.iacr.org/2012/437), [Lee et al. 2013](https://eprint.iacr.org/2013/762)).

**Revocation cannot erase a saved plaintext, key, DEK or old authenticated snapshot.** Bob's retained epoch-1 material keeps opening the retained epoch-1 record. Replacing the server's current header does not prove replicas were deleted, and rolling back both storage and its checkpoint defeats the local freshness test.

**The message space is one GT element.** Encrypting application data directly is not merely inefficient, it is impossible. The KEM/KDF/AEAD split is mandatory, and the AEAD's own properties — nonce uniqueness, associated data, tag length — are then yours to get right.

**Not constant-time.** JavaScript pairings leak timing freely. No side-channel claim is made anywhere in this repo.

**One demonstration is not a proof.** Watching a splicing attack fail shows the mechanism. It does not rule out attacks the page never attempts. The security argument is in the paper.

---

## Real-World Usage

ABE is deployed more narrowly than its literature suggests, and the gap is instructive. It appears in cloud data-sharing products (Zeutro's OpenABE lineage), in electronic health-record research systems where "any cardiologist on call" is the natural access rule, in pay-per-view and broadcast encryption, and in defence and intelligence pilots where clearance lattices map cleanly onto attribute sets. Its slow adoption is what motivated FAME in the first place: earlier fully secure constructions were either restricted in policy type or built on non-standard assumptions and composite-order groups, and were too slow to deploy.

The pieces surrounding it are entirely conventional. The KEM/KDF/AEAD envelope this lab shows is the same shape as HPKE, TLS record protection, and any sane file-encryption format.

---

## How to Run Locally

```bash
npm install
npm run dev        # http://localhost:5173/crypto-lab-attribute-gate/
```

```bash
npm run build      # tsc --noEmit && vite build
npm test           # Vitest: the full unit and KAT suite
npm run test:a11y  # axe-core WCAG 2.1 A/AA gate against the production build
npm run test:claims # the page-tells-the-truth suite
npx playwright install chromium   # once, before either browser suite
```

`npm run vectors:update` regenerates `vectors/fame-vectors.json`. The default test path only ever compares against it.

---

## Related Demos

- **[IBE Gate](https://systemslibrarian.github.io/crypto-lab-ibe-gate/)** — Boneh-Franklin identity-based encryption on the same curve. Same escrow property, over identities rather than policies. The natural predecessor to this lab.
- **[Pairing Gate](https://systemslibrarian.github.io/crypto-lab-pairing-gate/)** — the bilinear map itself, if `e(g^a, h^b) = e(g,h)^{ab}` is not yet second nature.
- **[HPKE Envelope](https://systemslibrarian.github.io/crypto-lab-hpke-envelope/)** — the same KEM → KDF → AEAD pipeline with a Diffie-Hellman KEM. Exhibit 1 here is that shape with an ABE KEM.
- **[Shamir Gate](https://systemslibrarian.github.io/crypto-lab-shamir-gate/)** — the secret sharing underneath the threshold gates, and the Lagrange reconstruction in its original setting.
- **[Threshold Decrypt](https://systemslibrarian.github.io/crypto-lab-threshold-decrypt/)** — the other way to split decryption authority: a quorum of key holders, rather than a rule over attributes.
- **[Credential Veil](https://systemslibrarian.github.io/crypto-lab-credential-veil/)** — proving you hold an attribute without revealing which. The privacy dual of encrypting to one.

---

## Build & Verify

**226 unit tests pass** across eight Vitest files. The separate browser claims suite and accessibility gate cover the production page at desktop, 380px and the 280px reflow-headroom width.

| Suite | What it covers |
|---|---|
| `src/fame/msp.test.ts` | Policy validation, the one-use transform and registry, the tree→MSP conversion, Lagrange, and equation 2.1 checked on **every satisfying subset** of five policy shapes |
| `src/fame/fame.test.ts` | Field arithmetic, bilinearity, the random oracle's typing, each of Figure 3.1's three key components recomputed from the witness, end-to-end round trips over a policy zoo, collusion, escrow, and NEG-1 |
| `src/fame/kat.test.ts` | **Published spec vectors**: RFC 9380 §J.9.1 G1 hash-to-curve (5) and §J.10.1 G2 hash-to-curve (5), RFC 5869 HKDF-SHA-256 (3), Wycheproof AES-256-GCM (6) |
| `src/fame/vectors.test.ts` | The pinned FAME vectors, and their **independent re-derivation** |
| `src/fame/system.test.ts` | The hybrid pipeline, the failure-code contract, the exhibits end to end |
| `src/fabesa/fabesa.test.ts` | Canonical encodings; independently recomputed Figure 5 Setup, KeyGen, Encrypt and Decrypt equations; public/hidden payload boundaries; bounded candidate enumeration; the tag oracle; authority, tampering and malformed-input negatives |
| `src/rw15/rw15.test.ts` | Exact asymmetric RW15 equations, independent share/row-term reconstruction, same- and cross-GID paths, repeated attributes, compromised-issuer boundaries, malformed inputs, component tampering and the hybrid wrapper |
| `src/revocation/epoch.test.ts` | Complete-key reissue, revoked/current and retained/old access, owner-assisted header rewrap, rollback checkpoints, both escrow paths, cross-user pooling, authenticated metadata and executed cost accounting |
| `e2e/a11y.spec.ts` | The WCAG 2.1 A/AA gate, driven through every state the page renders, at desktop, 380px and 280px |
| `e2e/claims.spec.ts` | Whether the page tells the truth — see below |

### On known-answer tests

**No official FAME vectors exist.** The paper publishes none and the authors' reference implementation pins none. So this lab does two things instead.

First, it runs **published vectors for every standardised primitive underneath** — the ones a wiring mistake would hide behind. If the hash-to-curve DST were handled wrongly, every group element in the scheme would be wrong *together* and the round-trip tests would still pass; RFC 9380's vectors are what make that impossible.

Second, it **pins its own**, in `vectors/fame-vectors.json`: a complete run — public key, master secret, five user keys, the ciphertext, a collusion residual, a threshold reconstruction and the KEM output — with **every intermediate element tagged with its group**. `src/fame/vectors.test.ts` then rebuilds those elements from the seed's scalars using only the pairing and field helpers, **never calling `setup`, `keygen`, `encrypt` or `decrypt`**, and checks the pairing equations against the pinned hex. A test that re-runs the implementation it is checking will agree with its own bugs; this one takes a different route to the same numbers.

**No official FABESA vectors are published either.** The FABESA suite therefore fixes test randomness, derives every Setup/KeyGen/Encrypt term independently from the sampled witnesses, checks the nontrivial reconstruction coefficients and verifies the recovered `GT` element. It also guards two transcription traps in the authors' demonstration artifact: Figure 5 has an independent `g3`, and both hash factors in `ct1` are exponentiated.

The RW15 suite follows the paper and the authors' asymmetric Charm implementation, then independently recomputes both authority public keys, both user-key components, every `v` and zero-sharing `w` share, every ciphertext row and the complete decryption identity. RFC 9380's five published BLS12-381 G2 vectors separately pin the hash-to-curve primitive used for `H(GID)` and `F(attribute)`; scheme-specific, distinct DSTs keep those two random-oracle domains apart.

### On the claims suite

`e2e/claims.spec.ts` asks whether the *page* is honest, which is a different question from whether the *code* is correct. It mixes cross-checks between two surfaces that must agree (a key card's element count against the labels it lists; the rendered failure-code table against the exported constants), independent re-derivations (the reconstruction recomputed from the numbers parsed back out of the rendered matrix, with a modular inverse computed by Fermat rather than by the extended Euclid the page uses), and parts-sum-to-whole checks (matrix columns against `1 + Σ(k−1)` over the gate controls on screen). It also checks FABESA's equal-public-payload comparison, observer/value boundary, sequential candidate ledger, actual pairing totals, generic negative outcomes, unexpected-error escalation, result retirement and fail-closed cap. RW15 checks distinguish structural policy satisfaction from the recovered `GT` element and final tag, including same-GID success, raw cross-GID failure, repeated attributes and one-authority compromise. Epoch checks cover current and retained access, issuance withholding, rollback with and without trusted state, byte-identical payload preservation, both escrow powers and the measured ledger. The suite retains the earlier revoked-key, two-step escrow, no-op and `[hidden]`-cascade fixtures.

### Proving the gates bite

A green suite is not evidence until it has been watched failing. The nine mutations below are replayed by a committed runner, `npm run test:mutations` (`scripts/mutations.mjs`), which CI runs on every pull request and push before the deploy job and whose `mutation-evidence.json` is uploaded as the `mutation-evidence` artifact. For each recipe the runner requires the unmodified copy to pass the whole unit suite and build, the ONE named owning test to be green, the patch to change the production bundle (JavaScript and CSS are hashed, because one recipe mutates the stylesheet), the owner to go red on a test failure — a timeout, a crash, a missing module or a preview server that failed to start is refused, not counted — and the source and bundle to be restored byte for byte with the owner green again. Measured on 2026-10-27: 9 of 9 caught. The "What it reported" column records the hand-applied runs that preceded the runner; the owning test named in each recipe is the single assertion the gate now relies on.

| Mutation | Owning gate | What it reported |
|---|---|---|
| `Decrypt` returns `den / num` instead of `num / den` | `fame.test.ts` | 10 failures — every round trip, both escrow cases, the collusion residual and NEG-1 |
| `indexedLabel` collapses every copy to `:1` (the reference implementation's index-stripping bug) | `msp.test.ts`, `vectors.test.ts` | Failures naming `ATTRIBUTE_REUSED: row label "Doctor:1" appears twice` |
| The Lagrange numerator loses its sign | `msp.test.ts` | 7 failures — the basis no longer sums to 1, and equation 2.1 fails on every policy shape |
| `--border-strong` degraded to the original token | `a11y.spec.ts` | Non-text contrast failures naming every button, select and input at 2.14:1 and 1.97:1 against a 3:1 requirement |
| FABESA `ct1` raises both hidden-value hashes by `s1`, discarding `s2` from the second branch | `fabesa.test.ts` | 6 failures — the independent Figure 5 equation, recovery, pinned fingerprint, one-row opening, two-candidate opening and no-expected-message check all reject the mutation |
| The hard FABESA candidate ceiling moves from 32 to 33 | `fabesa.test.ts` | The 3-of-7 fixture reports the changed bound instead of refusing at the required candidate 33 |
| RW15's GID random oracle hashes one constant identifier for every user | `rw15.test.ts` | 2 failures — distinct case-sensitive GIDs collide and the raw cross-GID pool recovers the protected value |
| The epoch gate changes from `business AND epoch` to `business OR epoch` | `epoch.test.ts` | 3 failures — Bob's old business key opens current data, owner rewrap no longer excludes it, and authority escrow mints only the business label |
| The trusted-checkpoint comparison accepts every well-shaped checkpoint | `epoch.test.ts` | 2 failures under the runner — the stale source checkpoint and same-epoch pseudo-update are accepted, and the executed cost ledger records the unauthorized rewrap; the runner's owner is "refuses a stale source checkpoint and a same-epoch pseudo-update" |

The first attempt at the first mutation is worth recording: replacing `gtDiv` with `gtMul` left `gtDiv` unused, `tsc` refused the build, and the suite would then have run against the previous bundle — a mutation that breaks the build proves nothing at all.

### The accessibility gate

`npm run build && npm run test:a11y` must pass with **zero violations** before anything deploys. The gate scans the production build in Chromium at desktop, 380px and 280px, driving the page through every state it renders — including the FAME refusals, `MALFORMED_POLICY`, collusion walkthrough, every disclosure opened through its own `<summary>`, FABESA success and negative paths, all three RW15 outcomes, and the complete epoch lifecycle. It asserts axe's `incomplete` bucket as well as `violations`, computes contrast arithmetically over composited surfaces (because every meaningful fill here is a `color-mix()` axe declines to resolve), measures non-text contrast against a ratcheting baseline, and adds the reflow and keyboard-reachability checks axe has no rules for.

---

## Performance

Wall-clock figures from a browser say more about the reader's machine than about the scheme, so what this lab quotes — and what it prints on screen — are **counts**, which are exact and load-invariant.

FAME's operation counts are:

| Operation | Cost |
|---|---|
| Setup | 1 pairing; 3 exponentiations in G1, 2 in G2, 2 in GT |
| KeyGen for an attribute set `S` | `6(\|S\|+1)` distinct oracle queries, `9(\|S\|+1)` G1 exponentiations, 3 in G2 |
| Key size | `3\|S\| + 6` group elements — `sk0` is 3 in G2, `sk'` is 3 in G1, and each attribute adds a triple in G1 |
| Encrypt over an `n1 × n2` MSP | `6(n1 + n2)` distinct oracle queries; `6n1` G1 exponentiations for the `s_t` factors plus one per non-zero matrix entry per `(ℓ, t)`; 3 in G2, 2 in GT |
| **Decrypt** | **6 pairings, whatever the policy is**, plus 3 G1 exponentiations per row the reconstruction uses |

The last line is FAME's headline result, and it is the reason the scheme exists: earlier fully secure CP-ABE constructions paid a pairing per attribute. Here decryption is six pairings for a two-row policy and six for a sixty-row one; everything that grows with the policy is exponentiation in `G1`, the cheap group. The oracle count is `6(n1 + n2)` rather than `6·n1·n2` because the column hashes are shared across every row — and the `n2` term is the same set of points `KeyGen` already queried for `sk'`, which is why the two sides agree at all.

That constant is **shown, not asserted**. Every FAME open-attempt verdict prints the number of pairings the attempt actually computed, counted at the primitive; `src/fame/system.test.ts` asserts it is exactly 6 for policies of different sizes, and 0 when the policy check fails before decryption runs. The one-use transform's cost is displayed the same way — the key-size column in exhibit 2 is a count, not a claim.

FABESA has a different cost shape:

| Operation | Cost in this bounded profile |
|---|---|
| Public candidate enumeration | Subsets of matching public names, stopped at 10 matched rows or before candidate 33 |
| Decrypt one candidate | Four pairing terms, plus three `G1` exponentiations per selected row |
| Hybrid open | Candidates are tried sequentially until AES-GCM authenticates; the page reports the actual pairing-counter delta for every attempt and the total |

Four pairing terms are therefore required **per candidate**, not per ciphertext search. A result that succeeds on candidate two normally executes eight nonidentity pairing calls; a paper-faithful zero-scalar identity case can execute fewer, which is why the page reports terms and measured calls separately. A public-name failure or candidate-bound refusal performs none. Search order and total work are visible leakage, not a privacy claim.

RW15 has a third cost shape. Each selected LSSS row evaluates one `GT` ciphertext component and exactly three pairing terms: `e(C2,K)`, `e(C3,H(GID))` and `e(K′,C4)`. The two-row same-GID and raw cross-GID fixtures therefore each execute six nonidentity pairing calls under ordinary fresh randomness. Encryption and key material grow with the applicable authorities, attributes and policy rows; RW15 does not inherit FAME's constant-six-pairing decryption result.

The epoch adaptation reports completed operations instead of a closed-form asymptotic claim. Its lifecycle ledger separates complete holder-key generations, authority-escrow key generation, FAME header encryptions, payload encryption, owner-capsule encryption, owner DEK unwraps, access-DEK wraps, access-header bytes, checkpoint writes and epoch/revocation transitions. A rewrap must report one owner unwrap and a new access header while payload encryptions and payload bytes rewritten remain zero; this says nothing about unmodeled indexing, network or bulk-update costs.

For orientation only, and not a benchmark: on an unloaded M-series laptop the page completes Setup, five KeyGens and an Encrypt in roughly a second, which is what the initial seal costs before anything is clickable.

---

*One of the browser demos in the [Crypto Lab](https://crypto-lab.systemslibrarian.dev/) suite.*

*"So whether you eat or drink or whatever you do, do it all for the glory of God." — 1 Corinthians 10:31*
