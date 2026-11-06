# ORIGIN TRADER

### An evolving trading intelligence platform.

**Intelligence with boundaries. Autonomy with accountability.**

---

## What is ORIGIN TRADER?

ORIGIN TRADER is an independent trading intelligence platform intended to analyse financial markets, evaluate trading opportunities, manage risk and improve its analytical capabilities.

The planned initial integration is with MetaTrader 5. ORIGIN TRADER is intended to operate as an independent intelligence engine rather than a conventional trading robot.

It aims to understand market conditions, evaluate its decisions, learn from experience and improve through controlled, evidence-based evolution.

## Implemented Capabilities

- OBSERVE-mode startup status display.
- TOML configuration loading and validation, restricted to OBSERVE mode.
- Structured JSON-lines operational logging.
- A basic SQLite event store supporting event persistence, reopening and schema version checks.

The SQLite store does not provide a reliable append-only guarantee: its current triggers do not prevent all mutation forms, including `INSERT OR REPLACE`. ORIGIN TRADER does not yet implement cryptographic tamper detection or signed audit checkpoints.

## Planned Capabilities

- Read-only MetaTrader 5 market-data integration.
- Market observation validation, statistical analysis and reporting.
- Independent risk governance and strategy evaluation.
- Cryptographic audit records and signed checkpoints.
- Self-evolution with isolated candidates and independent validation.
- Controlled execution architecture, subject to future security review and human authorization.

## The ORIGIN Philosophy

ORIGIN is built around five principles:

1. Preserve capital before pursuing profit.
2. Evidence before decisions.
3. Intelligence must operate within boundaries.
4. Improvements must prove their value.
5. Autonomy must remain accountable.

## Self-Evolution Vision

ORIGIN TRADER is intended to evaluate and improve both its trading strategies and its analytical intelligence. This capability is planned and is not implemented in the current repository.

Candidate improvements will require testing, independent validation and human approval before deployment.

No autonomous component will be permitted to weaken protected safety boundaries or approve its own deployment.

## Planned Technology Stack

- Python 3.12
- MetaTrader 5
- SQLite
- NumPy
- Pandas
- Pytest
- Git

## Development Status

**Current stage:** Foundation and architecture.

**Implemented today:** OBSERVE-mode startup display, validated configuration, JSON operational logging and a basic SQLite event store.

**Planned objective:** Connect to MetaTrader 5 in read-only mode, observe market conditions, analyse historical and current prices, and persist market observations.

ORIGIN TRADER is currently OBSERVE-only. No order execution is implemented, and no live trading is authorised.

Cryptographic tamper detection and signed audit checkpoints are not yet implemented.

## Project Vision

ORIGIN TRADER is the first step in a broader ORIGIN software vision: developing persistent, intelligent and autonomous software systems with controlled authority, continuous learning and accountable evolution.

---

**ORIGIN TRADER**

*Intelligence with boundaries. Autonomy with accountability. Continuous evolution through evidence.*
