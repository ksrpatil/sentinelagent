# SentinelAgent

**A Zero-Trust Security Framework for Autonomous AI Agent Systems in Federal Operations**

[![Paper](https://img.shields.io/badge/Paper-arXiv-red)](https://arxiv.org/abs/XXXX.XXXXX)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

## Overview

SentinelAgent provides formal verification of multi-agent AI delegation chains in federal operations. When Agent A delegates to Agent B, which invokes Tool C on behalf of User X, SentinelAgent answers: whose authorization chain led to this action, and at which point did the chain violate policy?

**Key Results:**
- 100% detection on authority escalation, AiTM tampering, cascade propagation, and forensic reconstruction
- 53.3% TPR on intent drift detection at 0.7% FPR (95% CI: [0.1%, 3.9%])
- DelegationBench: 210 federal scenarios across 10 domains and 8 attack categories
- First published mapping of 20 NIST SP 800-53 controls to agentic AI delegation

## Core Contributions

1. **Delegation Chain Calculus (DCC)** — Formal model with 5 verified properties
2. **Intent-Preserving Delegation Protocol (IPDP)** — Runtime enforcement via non-LLM Delegation Authority Service
3. **Federal Compliance Mapping Engine (FCME)** — 20 NIST SP 800-53 controls mapped to delegation attack surfaces

## Quick Start

```bash
pip install -r requirements.txt

# Run main evaluation
python sentinelagent_simulation_v3.py

# Run stress tests
python sentinelagent_stress_test.py

# Run LLM agent evaluation
python sentinelagent_llm_agent_eval.py
```

## Five Formal Properties

| Property | Type | Result |
|----------|------|--------|
| P1: Authority Monotonic Narrowing | Deterministic | 100% verified |
| P2: Intent Entailment Preservation | Probabilistic | 53.3% TPR, 0.7% FPR |
| P3: Policy Conjunction Preservation | Deterministic | 100% verified |
| P4: Forensic Reconstructibility | Deterministic | O(n), 100% verified |
| P5: Bounded Cascade Containment | Deterministic | 100% verified |

## Citation

```bibtex
@article{patil2026sentinelagent,
  title={SentinelAgent: A Zero-Trust Security Framework for Autonomous AI Agent Systems in Federal Operations},
  author={Patil, KrishnaSaiReddy},
  year={2026}
}
```

## Related Work

Paper 3 in a trilogy on government AI security:
1. [CivicShield](https://github.com/ksrpatil/civicshield) — Conversational AI chatbot defense
2. [RAGShield](https://github.com/ksrpatil/ragshield) — Knowledge base / RAG pipeline defense
3. **SentinelAgent** — Autonomous AI agent delegation security (this repo)

## License

MIT License. See [LICENSE](LICENSE).

