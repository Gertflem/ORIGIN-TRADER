# ORIGIN TRADER
## Technical Specification
- **Version:** 0.1
- **Status:** Initial architecture
**Platform:** Windows / Python / MetaTrader 5
**Initial operating mode:** OBSERVE

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

**ORIGIN TRADER**

*Intelligence with boundaries. Autonomy with accountability. Continuous evolution through evidence.*