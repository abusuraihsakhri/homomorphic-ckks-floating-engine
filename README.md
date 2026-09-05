# Homomorphic CKKS Floating Engine

> **Domain:** Post-Quantum Cryptography & Zero-Knowledge Architecture
> **Reference Guidelines & Standards:** `NIST FIPS 203/204/205, NIST SP 800-90B & ISO/IEC Standards`

<div align="center">

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
![Python](https://img.shields.io/badge/Python-3.10%20%7C%203.11%20%7C%203.12-3776AB.svg?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.111-009688.svg?logo=fastapi&logoColor=white)
![Audit Trail](https://img.shields.io/badge/Audit-HMAC--SHA256_Tamper--Evident-brightgreen.svg)
![Zero-PHI Guard](https://img.shields.io/badge/Guard-Zero--PHI_Outbound-blue.svg)
![Docker](https://img.shields.io/badge/Docker-Ready-2496ED.svg?logo=docker&logoColor=white)

</div>

---

## 📖 What It Does

**Homomorphic CKKS Floating Engine** is an analytical platform implementing a multi-agent evaluation engine with CKKS Fully Homomorphic Encryption (FHE) SIMD floating-point vector arithmetic capabilities. It processes task payloads through specialized worker agents that evaluate metrics against domain thresholds, enforce safety boundaries, and verify protocol conformance.

The system features a **Zero-PHI Outbound Interceptor** that blocks sensitive identifiers (SSNs, MRNs, phone numbers, patient names) from leaving the system, and a **Tamper-Evident HMAC-SHA256 Audit Trail** that cryptographically signs every evaluation and state transition.

---

## ⚙️ Key Capabilities & Algorithmic Modules

- **Multi-Agent Evaluation Engine**: Three specialized workers (InvariantQC, SafetyEscalation, ProtocolConformance) evaluate task payloads in parallel
- **Consensus Dossier Generation**: Aggregates worker alerts into a unified urgency assessment with cryptographic audit hash
- **Zero-PHI Outbound Guard**: AST and regex inspection blocking SSNs, MRNs, phone numbers, emails, DOBs, and patient identifiers
- **HMAC-SHA256 Audit Trail**: Chained, cryptographically signed logs with integrity verification
- **FastAPI REST API**: OpenAPI 3.1 endpoints for task evaluation, chat, and audit log retrieval
- **Prometheus Telemetry**: Operational metrics exporter for monitoring
- **Enrichment Suite**: 8 domain-specific benchmarking and analysis engines (performance, side-channel resistance, interoperability, bootstrapping, security proofs, NIST compliance, SIMD optimization, noise budget)

---

## 🚀 Installation

```bash
# Clone the repository
git clone https://github.com/abusuraihsakhri/homomorphic-ckks-floating-engine.git
cd homomorphic-ckks-floating-engine

# Install dependencies
pip install fastapi uvicorn pydantic pytest

# (Optional) Set audit key for persistent audit integrity
export AUDIT_SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
```

---

## 💻 CLI Quickstart & Usage

### 1. Single Task Evaluation (Audit)
```bash
python cli.py audit --task-id TASK-001 --target KEY-01 --primary 28.5 --secondary 14.2 --critical --status DISCORDANT
```

### 2. Supervisory Chat
```bash
python cli.py chat "What standard is applied?"
```

### 3. Batch CSV Processing
```bash
python cli.py batch -i sample.csv -o results.csv
```

### 4. Verify Audit Trail Integrity
```bash
python cli.py verify-audit
```

### 5. Launch REST API Server
```bash
python cli.py serve --host 127.0.0.1 --port 8000
```

### 6. Run Simulation Benchmark
```bash
python simulator.py 1000
```

### Parameter Reference
- `--task-id`: Unique task/case identifier
- `--target`: Entity, patient key, or genomic/cryptographic target
- `--primary`: Primary domain measurement or score (float)
- `--secondary`: Secondary kinetic or confidence score (float)
- `--critical`: Emergency escalation or high priority trigger (flag)
- `--status`: Status code or phenotype descriptor (e.g., NOMINAL, DISCORDANT_ANOMALY)

### Input Data Schema

| Field | Description | Requirement |
|:------|:------------|:------------|
| `task_id` | Unique task/case identifier | Required |
| `target_identifier` | Entity or target key | Required |
| `primary_metric` | Primary measurement or score | Required |
| `secondary_metric` | Secondary kinetic/confidence score | Optional (default: 0.0) |
| `is_critical_flag` | Emergency escalation trigger | Optional (default: False) |
| `status_descriptor` | Status code or phenotype | Optional (default: NOMINAL) |

---

## 🛡️ Security & Enterprise Architecture

* **Zero-PHI Outbound Interceptor:** Active regex inspection blocking SSNs, MRNs, phone numbers, emails, DOBs, and patient identifiers.
* **Tamper-Evident HMAC-SHA256 Audit Trail:** Chained, cryptographically signed logs for every evaluation and state transition. Uses a cryptographically secure random key if `AUDIT_SECRET_KEY` is not set.
* **Air-Gapped LLM Reasoning Adapter:** Agnostic integration for local Ollama instances (`llama3`, `mistral`), Claude 3.5 Sonnet, GPT-4o, and deterministic test mocks.
* **Active Learning Bayesian Calibration:** Dynamic tracker updating worker reliability weights and monitoring Brier calibration drift.
* **FastAPI & Prometheus Telemetry:** Exposes OpenAPI 3.1 REST endpoints and operational Prometheus metrics (`/metrics`).

---

## 🧪 Testing & Verification

Run the full automated test suite:

```bash
pytest -v
```

Execute high-throughput batch simulation benchmarks:

```bash
python simulator.py 1000
```

### Test Coverage
- **PHI Guard Enforcement**: Validates that sensitive identifiers are blocked
- **Worker Evaluation**: Tests each specialized worker's threshold logic
- **Supervisor Consensus**: Verifies multi-agent dossier generation and audit integrity
- **Audit Trail Security**: Confirms secure key generation and chain integrity
- **Enrichment Suite**: Validates all 8 domain engines produce distinct results
- **CLI Batch Validation**: Tests error handling for missing files and invalid data
- **Simulator Resilience**: Verifies graceful handling of edge cases

---

## 🐳 Container Deployment

### Docker Compose (Recommended)
```bash
# Copy environment template and configure
cp .env.example .env
# Edit .env to set AUDIT_SECRET_KEY

# Build and run
docker-compose up -d
```

### Docker Direct
```bash
docker build -t homomorphic-ckks-floating-engine .
docker run -p 8000:8000 -e AUDIT_SECRET_KEY=your-secret-key homomorphic-ckks-floating-engine
```

---

## 📁 Project Structure

```
homomorphic-ckks-floating-engine/
├── agents/                     # Core agent framework
│   ├── __init__.py            # Package metadata
│   ├── api.py                 # FastAPI REST endpoints
│   ├── base.py                # Security, PHI guard, audit trail
│   ├── models.py              # Pydantic schemas
│   ├── supervisor.py          # Multi-agent orchestrator
│   ├── workers.py             # Specialized evaluation workers
│   ├── llm_factory.py         # LLM provider factory
│   ├── learning.py            # Bayesian calibration engine
│   ├── metrics.py             # Prometheus metrics collector
│   └── streamer.py            # WebSocket telemetry broadcaster
├── ckks_fhe_engine/           # CKKS FHE engine module
│   ├── __init__.py
│   ├── agents.py              # Sub-agent implementations
│   ├── cli.py                 # CLI entry point
│   ├── engine.py              # Core algorithmic engine
│   ├── models.py              # Data models
│   └── server.py              # FastAPI server factory
├── tests/                     # Test suite
│   ├── test_ckks_fhe_engine.py
│   ├── test_enrichment.py
│   ├── test_homomorphic_ckks_floating_engine.py
│   └── test_security_and_reliability.py
├── web/index.html             # Operations console UI
├── cli.py                     # Main CLI entry point
├── simulator.py               # Stress testing simulator
├── enrichment.py              # Domain-specific enrichment engines
├── Dockerfile
├── docker-compose.yml
├── pyproject.toml
└── README.md
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
