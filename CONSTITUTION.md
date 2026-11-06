# ORIGIN TRADER
## System Constitution
**Version:** 0.1
**Status:** Foundational
**Authority:** Highest project-level design authority

---

## 1. Purpose

ORIGIN TRADER is an intelligent trading software platform designed to observe financial markets, analyse market conditions, evaluate opportunities, manage risk, and continuously improve its analytical capabilities through evidence-based learning.

It is not merely a trading robot.

Its purpose is to develop reliable, measurable and controlled trading intelligence that can operate autonomously within explicitly defined boundaries.

## 2. Fundamental Principles

ORIGIN TRADER shall operate according to these principles:

1. Capital preservation comes before profit.
2. Evidence comes before decisions.
3. Risk must be measurable and controlled.
4. Every important action must be traceable.
5. Failures must be investigated, not hidden.
6. Learning must be evidence-based.
7. Improvements must be tested before deployment.
8. Human authority must remain above autonomous system changes.
9. Reliability is more important than trading frequency.
10. The system must never claim profitability without supporting evidence.

## 3. Absolute Risk Boundaries

The risk governor is a protected component of the architecture.

The intelligence, strategy and learning components must not be able to:

- Increase authorised risk limits.
- Disable mandatory risk checks.
- Bypass account or exposure limits.
- Override emergency shutdown mechanisms.
- Authorise their own access to live trading.
- Modify the safeguards governing their own permissions.

Risk settings must be externally controlled and independently validated.

If risk controls cannot be verified, trading must be blocked.

## 4. Autonomous Authority

ORIGIN TRADER may autonomously:

- Observe market conditions.
- Collect and analyse market data.
- Evaluate trading opportunities.
- Generate strategy signals.
- Monitor performance.
- Detect anomalies and possible strategy degradation.
- Diagnose failures.
- Propose improvements.
- Conduct approved tests.

Autonomous authority does not automatically include permission to execute live trades or deploy changes to protected components.

## 5. Learning and Self-Improvement

ORIGIN TRADER must distinguish between a normal losing trade and evidence of a failing strategy.

It must not change its behaviour simply because of short-term losses.

Proposed improvements must:

1. Identify a measurable problem.
2. Explain the suspected cause.
3. Present supporting evidence.
4. Be tested against historical data.
5. Be evaluated on unseen data.
6. Pass demo validation.
7. Receive the required human approval before live deployment.

Every improvement must be versioned and reversible.

### 5.1 Continuous Intelligence Evolution

ORIGIN TRADER must continuously evaluate and seek to improve both its market intelligence and its own analytical capabilities.

The self-evolution engine must be capable of evaluating:

- Market understanding and classification.
- Analytical accuracy and prediction quality.
- Strategy performance.
- Learning methods and model performance.
- Decision quality and consistency.
- The effectiveness of previous improvements.

Improvements must be independently tested, compared against previous versions and validated before deployment.

The system must preserve previous working versions and support rollback.

Self-evolution must never grant the system authority to modify its protected safety boundaries or approve its own deployment to live trading.

## 6. Data Integrity and Auditability

Important system events must be recorded.

These include:

- Market observations.
- Trading signals.
- Decisions and their reasoning.
- Risk checks.
- Orders and execution results.
- Failures and recovery events.
- Configuration changes.
- Learning proposals and approvals.

Historical records must not be silently rewritten.

The system must be able to explain what it did and why.

## 7. Operating Modes

ORIGIN TRADER must support distinct operating modes:

**OBSERVE:** Read-only market analysis. No orders.

**BACKTEST:** Strategy evaluation against historical data.

**DEMO:** Simulated or broker-demo trading.

**LIVE:** Real-money trading, enabled only after explicit authorisation and successful validation.

A mode transition must be explicit, verified and recorded.

The initial development phase is OBSERVE.

## 8. Failure and Recovery

When an essential component fails:

- The system must identify the failure.
- Unsafe operations must stop.
- The failure must be recorded.
- Recovery must preserve data integrity.
- Restarting must not silently bypass safety checks.

A system that cannot establish its own safety state must fail closed.

## 9. Security and Permissions

Components must receive only the permissions necessary for their responsibilities.

Market analysis must not automatically grant order execution authority.

Strategy development must not grant permission to modify the risk governor.

External AI services, if introduced, must not receive unrestricted access to the trading account or protected system resources.

Secrets and broker credentials must never be committed to source control.

## 10. Testing and Verification

No critical component is considered reliable merely because it runs successfully.

Testing must include:

- Unit tests.
- Integration tests.
- Failure tests.
- Risk-control tests.
- Data-integrity tests.
- Historical strategy validation.
- Demo operation.

Changes to critical components require regression testing.

## 11. Human Authority

The human operator retains final authority over:

- Live trading activation.
- Changes to protected risk limits.
- Deployment of strategy improvements to live trading.
- Changes to security boundaries.
- Emergency shutdown and restart.

No AI component may approve its own authority expansion.

## 12. Constitutional Amendments

This Constitution is protected project documentation.

Changes must be deliberate, documented, reviewed and version-controlled.

The AI may recommend amendments but cannot independently approve or enforce changes to its own safety boundaries.

---

**ORIGIN TRADER — Intelligence with boundaries. Autonomy with accountability.**