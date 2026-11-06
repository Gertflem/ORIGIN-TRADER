# ORIGIN TRADER
## Technical Specification
- **Version:** 0.1
- **Status:** Initial architecture
- **Platform:** Windows / Python / MetaTrader 5
- **Initial operating mode:** OBSERVE

**Implementation status:** This document describes target architecture and planned capabilities. The current implementation is a foundation only; it does not yet implement the protected authority, cryptographic audit checkpoints, MT5 integration, market intelligence, or order execution described below.

---

# 1. System Overview

ORIGIN TRADER is an independent trading intelligence platform connected initially to MetaTrader 5.

It is responsible for market analysis, strategy evaluation, risk management, trading decisions, performance monitoring, persistent memory and controlled self-evolution.

MetaTrader 5 initially provides market data and the broker connection.

ORIGIN TRADER owns the intelligence and decision-making architecture.

The system must be modular, testable, auditable and expandable.

# 2. Core Architecture

The platform consists of the following components:

## 2.1 Core Engine

Responsible for:
- Starting and stopping the platform.
- Managing system lifecycle.
- Loading configuration.
- Coordinating components.
- Monitoring component health.
- Managing operating modes.

## 2.2 Market Data Engine

Responsible for:
- Connecting to MetaTrader 5.
- Retrieving historical price data.
- Receiving current market prices.
- Monitoring available instruments.
- Validating incoming data.
- Detecting missing or abnormal data.
- Normalising market information.

The market data engine must not execute trades.

## 2.3 Market Intelligence

Responsible for:
- Analysing price behaviour.
- Calculating technical indicators.
- Detecting trends and reversals.
- Measuring volatility.
- Identifying market conditions.
- Classifying market environments.
- Producing structured analytical observations.

## 2.4 Strategy Engine

Responsible for:
- Evaluating trading strategies.
- Generating potential trading signals.
- Measuring strategy performance.
- Comparing different approaches.
- Maintaining strategy versions.

Strategies must not directly execute orders.

## 2.5 Decision Engine

Responsible for:
- Evaluating market intelligence.
- Reviewing strategy signals.
- Assessing opportunity quality.
- Producing proposed trading decisions.
- Recording the reasoning behind decisions.

Every proposed decision must be explainable and traceable.

## 2.6 Risk Governor

This is a protected system component.

Responsible for:
- Calculating permitted exposure.
- Enforcing risk limits.
- Checking trade eligibility.
- Monitoring account exposure.
- Enforcing maximum loss limits.
- Blocking unsafe operations.
- Supporting emergency shutdown.

The risk governor must operate independently of the AI's authority.

No intelligence, strategy or learning component may override its restrictions.

## 2.7 Execution Engine

Responsible for:
- Managing approved trading instructions.
- Communicating with MetaTrader 5.
- Checking order conditions.
- Recording execution results.
- Monitoring open positions.

Execution must require successful risk approval.

During the initial development phase, execution is disabled.

## 2.8 Performance and Monitoring Engine

Responsible for:
- Tracking system performance.
- Recording trading results.
- Measuring analytical accuracy.
- Monitoring strategy degradation.
- Detecting abnormal behaviour.
- Generating performance reports.

It must distinguish between normal statistical variation and genuine performance deterioration.

## 2.9 Self-Evolution Engine

This is a core platform capability.

It must evaluate both trading performance and the quality of the intelligence itself.

Responsibilities include:

- Identifying weaknesses.
- Diagnosing analytical failures.
- Evaluating prediction accuracy.
- Comparing analytical models.
- Evaluating learning methods.
- Proposing strategy improvements.
- Proposing intelligence improvements.
- Testing candidate versions.
- Maintaining version history.
- Supporting rollback.

The evolution engine must never directly modify the live production system.

It creates candidate improvements for independent validation.

# 3. Self-Evolution Architecture

The evolution process follows this lifecycle:

1. OBSERVE — collect performance and analytical evidence.
2. DETECT — identify a possible weakness.
3. DIAGNOSE — investigate the cause.
4. PROPOSE — formulate a measurable improvement.
5. DEVELOP — create an isolated candidate version.
6. TEST — compare the candidate against the existing version.
7. VALIDATE — evaluate historical, unseen and demo results.
8. REVIEW — present evidence for approval.
9. DEPLOY — activate only after the required authorisation.
10. MONITOR — measure the new version's performance.
11. ROLLBACK — restore the previous version if required.

The system must preserve the previous approved version.

A new version must not be considered better simply because it performs better on historical data used during development.

# 4. Intelligence Architecture

ORIGIN TRADER must support multiple analytical methods.

Initial development will use deterministic statistical and technical analysis.

Potential future capabilities include:

- Machine learning.
- Statistical pattern recognition.
- Market regime classification.
- Predictive modelling.
- Model comparison.
- AI-assisted diagnostics.
- Natural-language explanations.

Advanced AI capabilities must be introduced only when they provide measurable value.

The architecture must not depend on expensive cloud AI services or dedicated GPU hardware.

# 5. Persistent Storage

SQLite will be the initial database.

The storage system must preserve:

- Market observations.
- Historical analytical results.
- Trading signals.
- Decisions.
- Risk evaluations.
- Trading records.
- Performance measurements.
- Evolution proposals.
- Model and strategy versions.
- Approval records.
- System events.

Important records must be traceable.

Database changes must be versioned and tested.

# 6. Security and Component Permissions

Components must have clearly defined responsibilities and permissions.

The system must prevent:

- Direct strategy-to-execution access.
- AI modification of protected risk settings.
- Unauthorised live trading.
- Unapproved candidate deployment.
- Exposure of broker credentials.
- Unrecorded configuration changes.

Critical safety controls must use independent validation and protected configuration.

Where necessary, separate processes and operating-system permissions will provide stronger isolation than ordinary Python module boundaries.

# 7. Operating Modes

The system will support four primary modes.

**OBSERVE**
- Read-only market observation.
- Analysis and reporting.
- No order execution.

**BACKTEST**
- Historical strategy testing.
- Statistical evaluation.
- No live orders.

**DEMO**
- Broker demo-account trading.
- Real market conditions without risking real capital.

**LIVE**
- Real-money trading.
- Requires explicit human authorisation.
- Requires completed validation.
- Requires active risk controls.

The initial product will operate exclusively in OBSERVE mode.

# 8. Technology Stack

Initial technologies:

| Component | Technology |
|---|---|
| Main language | Python 3.12 |
| Trading platform | MetaTrader 5 |
| MT5 integration | MetaTrader5 Python package |
| Data analysis | NumPy / Pandas |
| Database | SQLite |
| Testing | Pytest |
| Version control | Git |
| Development | Visual Studio Code |
| Future API | FastAPI |

All dependencies must be version-controlled.

The initial installation must remain lightweight and compatible with an 8 GB RAM Windows computer.

# 9. Testing and Validation

Every critical component requires automated tests.

Testing must include:

- Correct operation.
- Invalid input.
- Missing market data.
- Connection failures.
- Database failures.
- Risk-limit enforcement.
- Permission violations.
- Strategy evaluation.
- Evolution candidate validation.
- Recovery and rollback.

No strategy may be considered profitable based only on a successful backtest.

Validation must account for transaction costs, spreads, slippage, overfitting and changing market conditions.

# 10. Initial Development Milestones

**Milestone 1 — Foundation**
- Project architecture.
- Constitution.
- Technical specification.
- Configuration.
- Logging.
- Database foundation.

**Milestone 2 — MT5 Integration**
- Connect to MT5.
- Identify instruments.
- Retrieve historical candles.
- Retrieve current prices.
- Validate and store market data.

**Milestone 3 — Market Intelligence**
- Technical indicators.
- Market classification.
- Trend and volatility analysis.
- Structured market reports.

**Milestone 4 — Strategy Intelligence**
- Initial strategy.
- Signal generation.
- Decision evaluation.
- Historical backtesting.

**Milestone 5 — Risk Architecture**
- Risk governor.
- Exposure calculations.
- Risk validation.
- Safety tests.

**Milestone 6 — Demo Operation**
- Controlled demo execution.
- Performance monitoring.
- Trade recording.
- Failure handling.

**Milestone 7 — Self-Evolution**
- Performance diagnosis.
- Intelligence evaluation.
- Candidate improvements.
- Independent validation.
- Approval and rollback.

**Milestone 8 — Extended Validation**
- Long-running demo operation.
- Strategy robustness.
- Reliability testing.
- Security review.

**Milestone 9 — Commercial Readiness**
- Documentation.
- Installation process.
- User configuration.
- Monitoring interface.
- Product packaging.

# 11. Initial Acceptance Criteria

The first working milestone is achieved when ORIGIN TRADER can:

1. Start successfully.
2. Connect to MetaTrader 5.
3. Identify available trading instruments.
4. Retrieve historical market data.
5. Retrieve current market prices.
6. Validate incoming data.
7. Calculate initial market indicators.
8. Produce a structured market analysis report.
9. Save observations in SQLite.
10. Operate without placing any orders.

No profitability claim is required for this milestone.

---

# 12. Security Architecture and Requirements

This section specifies future requirements. The current implementation does not yet provide the protected authority, cryptographic audit checkpoints, MT5 integration, market intelligence or order execution described here.

## 12.1 Threat Model and Trust Boundaries

ORIGIN TRADER shall implement the universal ORIGIN Security Standard while remaining local-first and compatible with Windows, Python 3.12 and an 8 GB RAM development computer. Security controls must not depend on paid infrastructure or cloud services.

Treat MT5 data, configuration, strategy output, AI output and candidate artifacts as untrusted until independently validated. The protected authority shall own operating mode, permissions, risk policy, approval requirements and emergency-stop state. Strategy, intelligence and self-evolution components shall not modify or administer that authority.

The trusted computing base shall be kept small and include only components needed to validate evidence, enforce policy, write and verify audit records, and (in a future authorised phase) execute approved actions. Python module boundaries alone are not security boundaries. Before execution is introduced, the execution gateway shall be isolated using OS-enforced permissions and constrained interprocess communication (IPC). Until then, the product remains OBSERVE-only and order execution is unavailable.

Attacker categories and required handling:

1. **Accidental programming errors:** Use schema and input validation, narrow APIs, transactions, independent checks and regression tests. These reduce but cannot eliminate defects. Test invalid inputs, failed writes, boundary values and interrupted migrations.
2. **Malformed or malicious external inputs:** Validate type, schema, range, freshness, consistency and provenance before use. Validation cannot prove an upstream market feed is truthful. Test malformed, stale, duplicated, reordered, extreme and inconsistent data.
3. **Malicious code inside an application:** Strategy and candidate code must not receive credentials, signing keys, protected policy access or execution IPC. Separate processes and restricted permissions are required for untrusted code; same-process Python isolation is insufficient. Test hostile candidate attempts against the actual deployment boundary.
4. **Malware under the same Windows user:** User-scoped DPAPI, restrictive ACLs, key isolation and independent checkpoints provide defense in depth. Same-user malware may control the process or request use of user-accessible keys. Document this residual risk and test detection against independently retained checkpoints.
5. **Another local Windows user:** User-scoped key protection and ACLs restrict access to data, keys and IPC. Administrators may override local controls. Test denied access from a second non-administrative account.
6. **Local administrator or full operating-system compromise:** Independent offline checkpoints may reveal workstation manipulation. Local controls cannot reliably protect process memory, keys and evidence from full OS compromise. State this limitation explicitly; do not claim absolute security.

Subsystem permissions:

| Subsystem | Permitted authority | Prohibited authority |
|---|---|---|
| Market-data adapter | Read MT5 data and submit observations | Execute orders or certify its own observations |
| Validator | Check schema, freshness, provenance, ranges and evidence | Grant execution authority or modify source evidence |
| Intelligence and strategy | Read validated evidence and submit proposals | Access credentials, change risk policy, approve itself or execute |
| Self-evolution | Create isolated candidates and reports | Change policy, permissions, deployed artifacts, approvals or historical evidence |
| Protected authority | Enforce mode, policy, limits, permissions and approvals | Load strategy code or grant itself broader authority |
| Audit writer | Append through a narrow, validated interface | Expose arbitrary SQL or historical update/delete operations |
| Checkpoint signer | Sign approved checkpoint digests | Rewrite the database or approve trading |
| Future execution gateway | Execute fully authorised, scoped requests | Accept direct strategy instructions or infer missing approvals |

## 12.2 Database Integrity and Migration

SQLite is a local persistence mechanism, not a security boundary. Application APIs, SQLite triggers and schema constraints are defense in depth. Any process with write access to the database file may alter contents or schema; Windows ACLs shall restrict that access, while cryptographic verification shall detect alteration within the scope of a trusted checkpoint.

The event store shall expose a narrow write API and shall not expose its connection or unrestricted SQL to intelligence, strategy or candidate code. Audit writes shall use ordinary `INSERT`, verify exactly one row was committed, and treat conflicts or ignored inserts as errors. The application shall not use `INSERT OR REPLACE`, `UPDATE OR REPLACE`, UPSERT updates or `INSERT OR IGNORE` for historical events.

SQLite's `REPLACE` conflict algorithm deletes conflicting rows. Delete triggers for those replacement deletes fire only when recursive triggers are enabled. The recursive-trigger setting applies to an individual connection and does not constrain another connection opened directly on the database. The writer shall enable and verify the setting on every connection, but this setting and triggers shall not be presented as protection against direct database-file access. Tests shall cover `UPDATE`, `DELETE`, `INSERT OR REPLACE`, `UPDATE OR REPLACE`, UPSERT and `INSERT OR IGNORE` behaviour.

On startup and after migration, verify all of the following:

- Exact table and view names.
- Column names, declared types, nullability, defaults, primary keys and constraints.
- Expected indexes and indexed columns.
- Required trigger definitions and the absence of unexpected triggers.
- The supported schema version, application identifier and expected schema identifier.
- Database integrity using SQLite `integrity_check`.

If foreign keys are used, also run `foreign_key_check`, because `integrity_check` does not report foreign-key errors.

Migrations shall be version-specific and transactional. Before changing a database, create and independently verify a backup while preserving the original. Validate the source schema, migrate, then verify the new schema, data and sequence continuity, hash-chain continuity and integrity checks before commit. A malformed legacy database shall be rejected, not silently accepted or marked migrated. Interruption or failure shall leave the original or verified backup available. Never silently repair or discard a suspect database.

## 12.3 Cryptographic Audit Records

Important events shall use a versioned, reproducible canonical representation. RFC 8785 JSON Canonicalization Scheme (JCS) is the preferred event serialization standard, subject to fixed interoperability test vectors that pass across supported implementations. Specify field types, timestamp representation, sequence encoding, byte order and serialization rules. Reject ambiguous values; do not depend on unspecified Python serialization behavior.

Authoritative financial quantities shall be represented as validated decimal strings or integer minor units; uncontrolled binary floating-point values shall never be serialized as financial evidence. Monetary amounts shall use integer minor units with the currency's explicitly recorded scale. Prices, volumes and other instrument-specific quantities shall use canonical base-10 decimal strings with an explicit scale tied to versioned instrument metadata, including tick size and permitted volume step. Define maximum precision and scale for each quantity type and reject out-of-range values rather than silently rounding them. Calculations shall use decimal arithmetic with a fixed, documented precision. Each calculation shall specify its rounding mode and point of rounding: risk amounts shall round conservatively against available capacity, permitted order volume shall round down to the valid step, and price rounding shall follow a documented instrument- and direction-specific rule. Display rounding shall never feed back into risk or execution calculations. These rules must be fixed before financial quantities are used for risk decisions or execution.

Define each stream identity as a 16-byte UUID. Sequence numbers shall start at 1 and use unsigned 64-bit big-endian encoding. The previous-event hash shall be exactly 32 bytes; the genesis event shall use a fixed 32-byte zero value as its previous hash. Encode the canonical JSON byte length as an unsigned 64-bit big-endian integer. These fixed-width fields and the length prefix make the input unambiguous. The stream identity is included in every event hash, preventing events from being copied between streams without detection.

For event `n`, calculate:

```text
event_hash[n] = SHA-256(
    "ORIGIN-TRADER-EVENT\0" ||
    uint16_be(format_version) ||
    stream_uuid_bytes ||
    uint64_be(sequence_number[n]) ||
    previous_event_hash[n] ||
    uint64_be(length(canonical_event_bytes[n])) ||
    canonical_event_bytes[n]
)
```

SHA-256 is the baseline hash algorithm unless a later reviewed decision changes it. The event's stream identity, format version, sequence number, previous-event hash and canonical event bytes are all covered by the digest. Implementations shall publish fixed test vectors for genesis and ordinary events, including expected canonical bytes and digests.

Sequence assignment, previous-hash selection, event insertion and chain-head update shall occur atomically in one controlled transaction. A SQLite writer shall acquire the write reservation before reading the current head (for example, with `BEGIN IMMEDIATE`), assign the next sequence, calculate the event hash, insert the event and update the chain-head record with a compare-and-set condition on the previously read head. Commit only if every step succeeds and exactly one head row is updated. Otherwise roll back the event, sequence and head together. Other writers shall wait or fail and retry from the newly committed head; stale or competing heads shall be rejected. Concurrent writers must not create competing, skipped or inconsistent histories.

Periodic signed checkpoints shall include stream identity, format version, last sequence number, chain head, prior-checkpoint digest, checkpoint time and signing-key identifier. A restricted checkpoint signer shall never operate as a general-purpose signing oracle. Its only signing operation shall be for a validated checkpoint transition. It shall not accept arbitrary digests or messages, and it shall have no database write access or trading authority.

For each stream, the signer shall maintain a persistent, protected latest-checkpoint state containing at least the accepted sequence number, chain head, checkpoint digest and key identifier. Before signing, it shall independently validate:

- The checkpoint format and stream identity.
- Sequence progression and the previous trusted checkpoint.
- The chain-head structure and proposed transition from the protected previous-checkpoint state. The signer shall validate the intervening canonical events and recompute the chain head from the previously trusted head to the proposed head.
- The signing-key identifier and signing authorisation.

The signing authorisation shall be a one-time request bound to the stream UUID, sequence number, prior checkpoint digest, proposed chain head, key identifier, checkpoint purpose, expiry and nonce. The signer shall verify the issuer and reject replay.

Signing requests shall be serialized per stream. Repeating a request for the exact latest accepted checkpoint shall be idempotent and return the previously committed signature and receipt. A request older than the latest accepted checkpoint shall be rejected. A request with the same sequence number but a different digest shall also be rejected. A new checkpoint shall extend the latest accepted checkpoint and pass all transition checks before signing.

The signing-key operation and the protected-state store may be separate systems and may not participate in the same transaction. The implementation shall document the actual atomicity and durability guarantees of the selected protected signer store and its recovery procedure. It shall not claim atomicity across those systems unless the selected implementation explicitly provides it.

Signing operations shall recover safely from a crash or partial completion:

1. Before invoking the signing key, durably record a pending operation in protected storage. Bind it to the exact checkpoint details: canonical checkpoint digest, stream UUID, format version, sequence number, previous-checkpoint digest, proposed chain head, checkpoint time, key identifier, authorisation digest and request nonce.
2. After restart, resolve that pending operation before accepting any competing request for the same stream. Resume or safely complete only the bound request. Do not silently discard or replace the pending operation, or accept a conflicting checkpoint.
3. If signing succeeds but the protected-state commit fails, keep the signature unreleased and retain the pending operation. Do not accept another checkpoint request for that stream until recovery resolves the exact pending operation.
4. In the protected signer store, durably commit the signature, receipt and corresponding new latest-checkpoint state before returning the signature to the caller. This commit shall use the store's documented transaction and durability guarantees. Never release a signature whose corresponding protected checkpoint state and receipt have not been durably committed.
5. If the protected-state commit succeeds but the response is lost, a repeated request for that committed checkpoint shall return the previously committed signature and receipt. If the pending state or journal cannot be verified or recovered, refuse to sign and enter the restricted recovery path.

A hash chain detects edits only when checked against a trusted head. A signature establishes that the signing key signed particular bytes; it does not establish that event contents are truthful or that timestamps are independently trustworthy. If the database and all local checkpoint files are manipulable together, a local verifier cannot prove which checkpoint is newest. Retain checkpoints independently, preferably in an operator-controlled offline location. Without an independent latest checkpoint, report only that history is valid relative to the checkpoint available.

Key rotation shall be explicit and audited. Record old/new key identifiers and public keys; have both keys sign the transition when available; preserve the transition outside SQLite. If the old key is unavailable, mark continuity as broken and create a new trust epoch rather than implying that the new key validates prior history.

## 12.4 Windows Key and Credential Protection

The local-first baseline shall use user-scoped Windows DPAPI for persisted local secrets where appropriate, restrictive Windows filesystem ACLs for application data and key material, and separate handling for broker credentials and audit-signing keys. Do not use machine-scoped DPAPI for these secrets without an explicit reviewed requirement, because it broadens access to other users on the computer.

Apply restrictive ACLs to the database directory, database files, verified and unverified backups, and any SQLite journal or sidecar files, including rollback journal, WAL and shared-memory files. These files shall be created only inside the protected directory so that they inherit the intended ACL. Verify effective permissions during setup and recovery; a backup or sidecar with broader access invalidates the intended protection.

Evaluate Windows CNG key storage for a restricted, non-exportable signing key. Verify provider and key properties at runtime; do not assume a hardware-backed provider. A TPM-backed CNG key is optional only when the computer exposes and supports it. Credential Manager or user-scoped DPAPI may protect broker credentials; credentials shall never be stored in SQLite events, source, ordinary configuration or logs.

Same-user malware may invoke user-accessible keys or control the process. Administrators and full OS compromise remain outside local protection guarantees. Key loss, Windows profile loss or account recovery may make protected material unavailable. Define and test backup, rotation and recovery behaviour; do not silently substitute a new key while treating old history as verified.

## 12.5 Human Approval and Execution Authorisation

Keep these authorisations separate:

1. Approval to activate a future operating mode.
2. Approval to change protected risk policy.
3. Approval to deploy a specific intelligence or strategy version.
4. Authorisation for an individual trading action where policy requires it.

No AI, strategy, validator or self-evolution component may create its own required human approval. Bind each authorisation to the exact action and artifact or order digest, account, mode, policy version, limits, scope, expiry and one-time nonce. A change to the action invalidates the authorisation. Reject expired, replayed, mismatched, incomplete or unverifiable approvals.

Future execution shall require all of the following independently: valid operating mode; authorised operating-system and process permissions; sufficiently fresh and validated market evidence; successful risk approval from the protected authority; human approval where required; and a durable audit record. Human approval shall not override a risk denial. Failure to verify any gate shall block execution. Configuration alone shall never activate orders.

## 12.6 Self-Evolution Isolation

Run candidates in an isolated workspace without access to broker credentials, signing keys, protected policy files or execution IPC. Candidates shall receive read-only evidence snapshots. An independent validator shall produce and record results; candidates shall not author their own pass result.

Bind deployment approval to candidate artifact digest, validation report digest, target version, scope and expiry. Any changed artifact or report invalidates approval. Historical performance evidence shall be read-only to candidates; new evaluations shall be appended as new records. Preserve approved versions and audit deployment, rejection and rollback actions.

## 12.7 Logging, Monitoring, Failure and Recovery

Operational logs are diagnostic records and are not authoritative audit evidence. Audit records are structured, chained events covered by signed checkpoints. Operational logging shall use an allowlist of fields and redact credentials, tokens, account identifiers and sensitive trading information. Do not serialize arbitrary exception or input payloads without reviewing them for secrets.

Monitor startup integrity checks, schema and signature failures, mode/policy/permission changes, rejected evidence, denied or replayed approvals, key events, migration outcomes, audit-write failures, checkpoint failures and self-evolution lifecycle events. Integrity failure must be visible even when the audit store is unavailable.

Before relying on history, verify schema, database integrity, chain continuity, checkpoint signature and key history. If integrity, policy, evidence, permissions or approval cannot be established, enter OBSERVE or restricted state and block orders. Preserve suspect database and checkpoint files. Do not silently rebuild triggers, rewrite records, auto-advance schema or create a replacement trusted key. Allow only clearly marked forensic reads or exports. Recovery requires an explicit human decision, records the unverifiable interval, and retains original evidence until its disposal is approved.

## 12.8 Security Acceptance Tests

Security tests shall include:

- Rejecting update, delete, replacement, UPSERT modification and silent ignored-insert cases through the supported API.
- Demonstrating which raw SQLite operations bypass application controls, including connection-specific recursive-trigger behavior.
- Detecting altered, reordered, inserted, deleted or truncated history against an independently retained checkpoint.
- Rejecting malformed schemas, unexpected triggers, incompatible versions and failed migrations without marking the source migrated.
- Testing transaction interruption, backup verification, restore and recovery without destroying suspect originals.
- Verifying key material is absent from SQLite, source, ordinary configuration and logs; verifying access denial under another local account.
- Rejecting expired, replayed, wrong-account, altered-scope and artifact-mismatched authorisations.
- Verifying hostile candidate code cannot reach protected policy, keys, credentials or execution IPC in the intended OS configuration.
- Blocking execution when any mode, evidence, risk, permission, approval, audit or integrity gate is unavailable.
- Running Windows ACL, filesystem and recovery tests on supported Windows versions.

Passing these tests does not establish protection against full administrator or OS compromise, same-user malware, or unknown implementation defects.

**ORIGIN TRADER**

*Intelligence with boundaries. Autonomy with accountability. Continuous evolution through evidence.*
