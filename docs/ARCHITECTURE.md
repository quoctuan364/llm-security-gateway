# Architecture Design Document

## 1. Executive Summary

**Aegis LLM Security Gateway & Privacy Firewall** is a production-grade, self-hostable reverse proxy and defense gateway positioned directly between upstream client applications / autonomous AI agents and downstream Large Language Model (LLM) providers (OpenAI, Anthropic, Gemini, Ollama, vLLM).

The gateway provides rigorous, deterministic, low-latency inspection and enforcement across all ingress prompts and egress completions, protecting enterprise assets against prompt injection, jailbreaks, PII leakage, denial-of-wallet attacks, and unauthorized tool invocations.

---

## 2. Request & Response Processing Pipeline

The core architectural invariant is a deterministic, composable, fail-closed pipeline:

```text
[Client / Agent]
       │
       ▼ (1) TLS Ingress / Reverse Proxy
[FastAPI Gateway Engine]
       │
       ├─► (2) Authentication & Secret Verification (Hashed API keys, RBAC)
       ├─► (3) Concurrency & Rate Limiting (Redis Token Bucket / Leaky Bucket)
       ├─► (4) Token Budget & Financial Spend Quota (Atomic Redis Reservation)
       │
       ▼ (5) INGRESS INSPECTION ENGINE
       ├─► PII & Sensitive Credential Scanner (Regex, Checksum, Entropy)
       ├─► Masking / Redaction / Tokenization (Vietnamese ID, Card, Keys)
       ├─► Prompt Injection & Jailbreak Classifier (Heuristic + Semantic Risk)
       ├─► Agent Tool Execution Permission Validator (Least Privilege, Schema)
       │
       ▼ (6) POLICY ENGINE
       ├─► Evaluate Hierarchical Rules (Org > Project > Key > Default)
       ├─► Action Resolution: ALLOW | REDACT | WARN | BLOCK | REQUIRE_APPROVAL
       │
       ▼ (7) PROVIDER ADAPTER LAYER (Circuit Breaker & Fallback)
[Downstream LLM: OpenAI / Claude / Local Mock]
       │
       ▼ (8) EGRESS INSPECTION ENGINE
       ├─► Output Safety & PII De-leakage Filter
       ├─► Hallucinated Credential & Sensitive Extraction Guard
       ├─► Streaming Chunk Inspector (Sliding Window Buffer)
       │
       ▼ (9) AUDIT & OBSERVABILITY LAYER
       ├─► Cryptographically Chained Audit Log (SHA-256 HMAC integrity)
       ├─► Prometheus Metrics & OpenTelemetry Spans
       │
       ▼ (10) Settle Budget & Stream / Return Response
[Client / Agent]
```

---

## 3. Component Breakdown

### 3.1. `apps/api` (FastAPI Gateway Core)
- High-performance asynchronous HTTP gateway using FastAPI and Uvicorn.
- Routes:
  - `/v1/chat/completions` (OpenAI-compatible drop-in proxy).
  - `/v1/guard/inspect` (Standalone security inspection endpoint for custom pipelines).
  - `/v1/tools/authorize` (Agent tool execution permission validation).
  - `/v1/admin/*` (Key management, policy definitions, audit explorer, analytics).
  - `/health`, `/metrics` (Prometheus metrics & readiness probes).

### 3.2. `packages/security-engine`
- **Detectors**:
  - `PromptInjectionDetector`: Heuristic multi-pattern analysis, instruction override detection, delimiter collision, role confusion.
  - `PIIDetector`: Multi-pattern scanner with Luhn checksum validation for payment cards, Vietnamese Citizen ID (CCCD 12 digits, valid birth/province codes), VN phone numbers (+84 / 09, 08, 07, 03, 05), emails, AWS/GitHub/OpenAI API keys.
  - `ToolSecurityEngine`: Schema verification, dangerous function call prevention (e.g. arbitrary bash/shell injection), parameter sanitation.
- **Policies**:
  - Hierarchical policy resolution (Org -> Project -> API Key).
  - Risk scoring with configurable thresholds (Low, Medium, High, Critical).
  - Action dispatch: Allow, Redact, Warn, Block.

### 3.3. `packages/provider-adapters`
- Abstract provider base interface (`BaseLLMAdapter`).
- `MockProviderAdapter`: Deterministic local testing without network calls or paid API keys.
- `OpenAICompatibleAdapter`: Connects to OpenAI, Azure OpenAI, Ollama, or vLLM.
- Resilient transports with retry loops, exponential backoff, and circuit breakers.

### 3.4. `packages/shared`
- Standard schemas: Pydantic v2 data transfer objects, security decision metadata, audit record models.
- Cryptographic utilities: Hashing (Argon2 / SHA-256 HMAC), tamper-evident chain verification.

### 3.5. `apps/web` (Security Dashboard)
- Next.js 15 (App Router) + TypeScript + Tailwind CSS.
- Operational security views:
  - Real-time Threat & Attack Stream.
  - PII Detection & Redaction Inspector.
  - Policy Simulation & Live Rule Testing Playground.
  - Spend & Token Rate Limiting Monitor.
  - Tamper-Evident Audit Log Verification.

---

## 4. Data Storage & State Architecture
- **PostgreSQL**: System of record for Organizations, Projects, API Keys (hashed with salt), Security Policies, Tool Definitions, and Immutable Audit Records.
- **Redis**: Low-latency atomic state for:
  - Distributed Rate Limiting (Token Bucket).
  - Real-time Concurrency tracking.
  - Token Budget reservation & settlement.
  - Ephemeral cache for policy lookup.
