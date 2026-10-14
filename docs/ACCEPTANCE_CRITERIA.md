# Acceptance Criteria & Verification Standards

To guarantee production readiness and avoid superficial implementations, every component must satisfy rigorous verification criteria:

## 1. Gateway Core & API Ingress
- [ ] Accepts requests matching the OpenAI `/v1/chat/completions` schema.
- [ ] Validates client API keys via hashed SHA-256 / constant-time lookup.
- [ ] Rejects unauthorized requests with RFC 7807 compliant JSON problem details.
- [ ] Returns custom security headers: `X-Security-Risk-Score`, `X-Security-Decision`, `X-Correlation-ID`.

## 2. Privacy Firewall & PII Redaction
- [ ] Correctly identifies and redacts:
  - Vietnamese Citizen IDs (12 digits with valid structure).
  - Vietnamese Phone Numbers (+84 / 09, 08, 07, 03, 05).
  - Valid Payment Cards (passing the Luhn algorithm; rejects invalid card digits).
  - Standard Email Addresses.
  - High-entropy API keys (OpenAI `sk-...`, AWS `AKIA...`, GitHub `ghp_...`).
- [ ] Never logs raw PII in stdout, log files, OpenTelemetry traces, or database records.
- [ ] Reversible placeholder restoration works when authorized by policy.

## 3. Prompt Injection & Jailbreak Defense
- [ ] Detects known adversarial prefixes (instruction overrides, roleplaying jailbreaks, delimiter confusion).
- [ ] Computes a continuous risk score from `0.0` to `1.0`.
- [ ] Applies configured action (ALLOW, REDACT, WARN, BLOCK) based on policy threshold.
- [ ] Includes automated adversarial test suite with at least 20 real-world prompt injection samples.

## 4. Rate Limiting & Denial-of-Wallet Protection
- [ ] Enforces requests-per-minute (RPM) and tokens-per-minute (TPM) limits using atomic Redis scripts.
- [ ] Supports per-project and per-key daily/monthly financial spending budgets.
- [ ] Prevents race conditions under concurrent load (passes 50 concurrent request stress test).

## 5. Agent Tool Security
- [ ] Evaluates tool execution schemas against permission tiers (READ_ONLY, SENSITIVE, DESTRUCTIVE).
- [ ] Rejects undeclared tools and model-hallucinated arguments.
- [ ] Enforces mandatory human approval for destructive operations.

## 6. Audit & Cryptographic Integrity
- [ ] Every request creates an append-only audit record.
- [ ] Records include SHA-256 HMAC hash chaining (`current_hash = HMAC(prev_hash + record_data)`).
- [ ] Provides an automated verification script to detect database record alteration.

## 7. Developer Experience & Local Testing
- [ ] `docker-compose up` spins up PostgreSQL, Redis, API Gateway, and Dashboard with one command.
- [ ] Built-in Mock LLM adapter allows running all tests and local demos without paid third-party API keys.
- [ ] Automated Pytest suite achieves >85% code coverage.
