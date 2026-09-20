# Workload Network Contract 1.0.0

A vendor-neutral C++20 runtime for declaring, validating, versioning, and
governing the explicit network requirements attached to an AI workload: the
bandwidth, latency, jitter, loss, locality, isolation, priority, failure-domain,
and lifecycle obligations that a specific workload generation states it needs,
which of those are mandatory, which are preferred, which are satisfiable under
the evidence that has been supplied, and which dependent decisions become stale
when the contract changes.

The question this repository answers is:

> What network obligations does this exact workload generation require, which are
> mandatory versus preferred, which are satisfiable under current evidence, and
> which dependent decisions become stale when the contract changes?

## 1. Boundary

This runtime owns the **contract**: its schema, identity, versioning, validation,
compatibility, lifecycle, provenance, change semantics, and the assessment of
satisfaction against evidence that other systems supply.

It deliberately does **not** own, implement, or observe:

* workload scheduling, placement, or admission;
* routing, path selection, or traffic engineering;
* bandwidth allocation or QoS enforcement;
* topology discovery, link-state measurement, or telemetry collection;
* hardware capability detection of any kind.

Those systems are adjacent consumers or producers. They hand this runtime a
contract to validate, or an evidence snapshot to evaluate against, through the
narrow interfaces in `include/wnc/contract.hpp` and `include/wnc/evaluation.hpp`.
Nothing in this repository opens a network interface to discover anything, and
nothing in it claims that a requirement has been enforced. A verdict of
SATISFIED means "the supplied evidence supports this requirement", never "the
network is currently providing it".

## 2. Core model and authority

### 2.1 Identities and generations

All public identifiers are strongly typed 64-character lowercase hex SHA-256
digests (`wnc::Id<Tag>`): `WorkloadId`, `ContractId`, `RequirementId`,
`ScopeId`, `PublisherId`, `CoordinatorId`, `PolicyId`, `EvidenceId`, and so on.
A matching identifier is never by itself evidence of a current generation:
identity and generation are separate values everywhere in this boundary.

Generations are separate, tagged counters (`wnc::Gen<Tag>`) that strictly
advance. Every boot of the coordinator assigns a fresh 16-byte incarnation and a
strictly increasing epoch. Durable state is bound to both.

### 2.2 Requirements

A requirement names a scope, a kind, a strength, and a constraint:

| Field | Meaning |
| --- | --- |
| `kind` | one of `min_bandwidth`, `max_latency`, `max_jitter`, `max_loss`, `locality`, `path_diversity`, `failure_domain_separation`, `security_class`, `traffic_priority`, `burst_allowance`, `collective`, `checkpoint_isolation`, `disaggregated_affinity`, `maintenance_tolerance`, `attribute` |
| `strength` | `required`, `preferred`, or `informational`; ordered, so required outranks preferred outranks informational |
| `target` | the strict bound |
| `minimum` | the weakest still-acceptable bound |
| `value` | the textual value for kinds that are not numeric |
| `key` | disambiguates several requirements of the same kind inside one scope |

Numeric kinds have a direction. A **floor** kind (`min_bandwidth`,
`path_diversity`, `failure_domain_separation`, `traffic_priority`,
`burst_allowance`) is stronger when it is higher; a **ceiling** kind
(`max_latency`, `max_jitter`, `max_loss`) is stronger when it is lower. A
`required` requirement has no preferred band, so its target must equal its
minimum; a `preferred` requirement must declare a distinct band.

### 2.3 Satisfaction

`Satisfaction` is `satisfied`, `unsatisfied`, `unknown`, or `not_applicable`.
Every verdict carries the stable reason code it was reached with, the evidence
entry it was decided from, and that entry freshness.

**Missing evidence yields UNKNOWN, never SATISFIED.** One function decides a
requirement (`wnc::decide_requirement`), and it returns `unknown` for an absent
entry, for an entry captured by another incarnation, for an entry marked stale
or expired, and for an entry that does not carry the dimension the requirement
needs.

### 2.4 Authority rules

* A contract submission carries a signature. The publisher identity is **derived
  from the verified signature** over the canonical bytes, using a key the
  coordinator already trusts for that publisher (`wnc::TrustSet`). A provenance
  field supplied by the submitter is never trusted on its own.
* The coordinator, not the publisher, owns generation order. Registering a
  workload fixes generation 1; publishing requires exactly the next generation
  and the digest of the current one. A repeated submission is refused as a
  replay, a skipped generation is refused as a gap.
* Only the publisher that owns the current generation may supersede it.
* A trust set change invalidates the state directory: a journal written under
  one trust root is refused under another rather than silently re-blessing
  publisher identities.
* Restoring state is never restoring liveness. Evidence captured by an earlier
  incarnation returns as `revalidation_required`; a cached decision produced by
  an earlier incarnation is never served, and is recomputed or reported as
  unknown instead.

## 3. Deterministic decisions and denial reasons

Every denial is a stable `wnc::Code` with a stable token, rendered by
`wnc::code_token`. Failures are never bare booleans. Examples:

| Token | Raised when |
| --- | --- |
| `json_duplicate_key` | an object repeats a key |
| `contract_digest_mismatch` | the declared digest does not describe the canonical body |
| `weakening_denied` | an overlay would weaken a stronger requirement |
| `composition_conflict` | two layers state incomparable constraints on one key |
| `replay_rejected` | a generation that was already applied is submitted again |
| `publisher_not_trusted` | the signing key is not in the trust set |
| `revalidation_required` | evidence belongs to an earlier incarnation |
| `evaluation_no_evidence` | no evidence covers the requirement scope |

## 4. Persistence semantics

State lives in one directory and consists of:

| Path | Role |
| --- | --- |
| `head.bin` | boot record: format version, coordinator identity, trust digest, epoch, incarnation, boot count |
| `journal-NNNNN.log` | append-only, integrity-checked, chained records |
| `snapshot.bin` | a derived index; never an authority |
| `lock.bin` | cross-process exclusive lock on the directory |

Each journal record is framed with a magic, a format version, a record type, a
strictly increasing sequence, a payload length, a SHA-256 of the payload, a
SHA-256 chain value over the previous chain and this record, and a CRC-32 over
the header. A torn tail is detectable, is truncated on recovery, and is
**reported** through `RuntimeInfo::recovered` and `truncated_bytes` rather than
being hidden.

Durable mutation order is fixed:

> plan, validate authority, prepare, append (durability point), flush, commit in
> memory, publish the authoritative result.

An acknowledgement is only produced after the append has been flushed to the
operating system, so it can never precede the durability point it claims.
Durability here means durability against process death (`FlushFileBuffers` on
Windows, `fsync` on POSIX). No claim is made about media failure or about power
loss that defeats the storage controller own cache.

A snapshot whose sequence is ahead of the journal is refused with
`recovery_required`: it would claim a state the journal cannot back. A journal
with no head record is refused rather than reused, because the epoch could no
longer be shown to advance.

## 5. Process, epoch, and generation behaviour

* Every boot allocates a fresh incarnation and increments the epoch persisted in
  `head.bin`. Incarnations are never reused.
* Evidence carries the incarnation that captured it. After a restart every
  restored entry is stamped `revalidation_required`, and a decision that
  depended on it returns UNKNOWN with `revalidation_required` as the reason.
* A contract generation change, a policy generation change, an evidence
  generation change, retirement, or a restart invalidates the cached decision
  for that workload; the invalidation reason is recorded.
* A request that names a coordinator incarnation or epoch other than the current
  one is refused with `wrong_coordinator_incarnation`.

## 6. Proof surfaces, and what is synthetic

| Surface | Label | Notes |
| --- | --- | --- |
| Contract schema, canonical form, digest | REAL | deterministic; no environment input |
| Ed25519 signing and verification | REAL | RFC 8032 vectors; self-contained implementation |
| Journal append, recovery, torn tail | REAL | real files, real process kills |
| Coordinator loopback TCP transport | REAL | real sockets, real operating system processes |
| Declared topology, capacity, and capability evidence | SYNTHETIC | supplied by the operator or a test; this runtime has no discovery path |
| Bandwidth, latency, loss, jitter, RDMA, NVLink, InfiniBand, RoCE, programmable switches | SYNTHETIC | no such hardware is present, and no claim of physical validation is made |
| AddressSanitizer coverage | UNSUPPORTED on the reference host | the MSVC ASAN runtime is not installed; see the final report |

Nothing in this repository fabricates hardware capability. Every dimension a
test exercises is either a value the test itself supplied, or a real file, a
real socket, or a real operating system process.

## 7. Build, test, install, and consume

```
cmake -S . -B build/release -DCMAKE_BUILD_TYPE=Release
cmake --build build/release
ctest --test-dir build/release --output-on-failure
cmake --install build/release --prefix <clean-prefix>
```

Options: `WNC_BUILD_TOOLS`, `WNC_BUILD_TESTS`, `WNC_BUILD_EXAMPLES`,
`WNC_BUILD_SHARED`, `WNC_SANITIZER`, `WNC_HARDENING`, `WNC_STRICT_WARNINGS`.

A downstream consumer uses the installed package:

```cmake
find_package(workload-network-contract 1.0 REQUIRED)
target_link_libraries(consumer PRIVATE WorkloadNetworkContract::wnc)
```

Examples that execute real supported paths live in `examples/`.

## 8. Public API sketch

```cpp
#include "wnc/contract.hpp"
#include "wnc/runtime.hpp"

wnc::Contract contract;
contract.body.workload.id = workload_id;
contract.body.generation.value = 1;
// scopes and requirements
wnc::canonicalize(contract);
const std::string body = wnc::contract_body_to_json(contract.body).dump();
const wnc::SignatureBytes signature =
    wnc::sign_with_local_signer(signer, "wnc/v1/submission/registration", body);

wnc::Runtime::Options options;
options.state_directory = state_directory;
options.trust = trust;
wnc::Code code = wnc::Code::kOk;
std::string message;
std::optional<wnc::Runtime> runtime = wnc::Runtime::open(options, code, message);
const wnc::RegisterResult registered = runtime->register_workload(contract);
const wnc::EvaluationResult evaluated = runtime->evaluate(workload_id);
```

## 9. Verification status

The state below is what the reference host actually produced, not a plan.

| Surface | Suite | Result |
|---|---|---|
| Unit: core, JSON, crypto, contract, policy, evaluation, runtime | 7 executables | pass |
| Property | `wnc_test_property` | 7/7 pass |
| Adversarial | `wnc_test_adversarial` | 8/8 pass |
| Persistence | `wnc_test_persistence` | 10/10 pass |
| Concurrency | `wnc_test_concurrency` | 6/6 pass |
| Protocol | `wnc_test_protocol` | pass |
| Integration | `wnc_test_integration` | pass |
| Multiprocess | `wnc_test_multiprocess` | 3/3 pass |

```
$ ctest --test-dir build/dev
100% tests passed, 0 tests failed out of 14
```

Both `Debug` and `Release` configurations pass the same 14 suites with
`/W4 /WX`. The library installs with `cmake --install` and a downstream project
consumes it with `find_package(workload-network-contract 1.0.0 REQUIRED CONFIG)`
and `WorkloadNetworkContract::wnc`, with no reference to this source tree.

Defects found and fixed during verification, each of which changed behaviour:

* **Contract identity was derived from freed memory.** `derive_contract_id`
  placed the temporary returned by `hex_encode` into a `std::string_view` array
  element, so the identity was computed from bytes the allocator had already
  reclaimed. It produced a different identity for identical content under
  concurrent load. The same mistake was present in `derive_policy_id`,
  `derive_evidence_id`, and the coordinator identity derivation.
* **The head record never advanced its epoch.** `Ledger::open` read the stored
  epoch and boot count into the record it then rebuilt, so both were reset before
  being incremented; a restarted coordinator reported epoch 1 forever.
* **The journal chain digest excluded the link field**, so a doctored link was
  invisible to verification.
* **A doctored record was treated as a torn tail** and silently truncated, which
  destroyed evidence of tampering. Only a frame that ends early is a torn tail.
* **The contract decoder materialised requirements before checking the bound**,
  so an oversized document allocated first and was refused second.
* **Overlay composition deleted every requirement that carried an identity**,
  so a composed body was always empty.
* **Evidence identity was derived before the entries were stamped**, so every
  durable evidence record was refused on recovery.
* **Evidence freshness was forced on decode**, which made a decoded document
  disagree with its own identity; freshness is now decoded as written and
  re-stamped by the coordinator when it loads a durable record.
* **A property test read elements of two different temporaries in one
  expression** (`first.reasons()[i] == second.reasons()[i]`), an access
  violation that aborted the process after the test had already reported
  success. The test now binds both lists first.

Reproduce the closure proof from a clean tree:

```
cmake -S . -B build/dev -G Ninja -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_C_COMPILER=cl -DCMAKE_CXX_COMPILER=cl
cmake --build build/dev
ctest --test-dir build/dev --output-on-failure
```

## 10. Limitations actually observed

* **No network observation.** Every satisfaction verdict is a statement about
  supplied evidence. There is no probe, no active measurement, and no capability
  discovery in this repository.
* **Ed25519 is not constant time.** The implementation favours auditability over
  timing resistance and is used for offline contract signing and verification,
  not inside an attacker-observable timing oracle. It has not been independently
  audited.
* **Durability is process-crash durability.** Power loss and storage-controller
  cache loss are out of scope, as described in section 4.
* **One coordinator instance owns a state directory.** Concurrency is handled by
  the single-threaded transport loop plus the directory lock, not by distributed
  consensus among coordinators.
* **Sanitizer coverage is unavailable on the reference host.**

## License

Apache License 2.0. Copyright 2026 Summon Software Labs. No telemetry transmission.
