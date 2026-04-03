# SentinelAgent

**Intent-Verified Delegation Chains for Securing Federal Multi-Agent AI Systems**

[![Paper](https://img.shields.io/badge/Paper-IEEE%20TDSC-blue)](https://doi.org/TBD)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Overview

SentinelAgent is a formal framework for verifiable delegation chains in federal multi-agent AI systems. The Delegation Chain Calculus (DCC) defines seven properties — six deterministic and one probabilistic — enforced at runtime by a non-LLM Delegation Authority Service (DAS).

The three-point verification lifecycle achieves **100% TPR at 0% FPR** on DelegationBench v4 (516 scenarios, 10 attack categories, 13 federal domains).

## Architecture

```
User → [P2: Intent Check] → DAS → [P1: Scope Narrowing] → Agent
                                        ↓
                              [P6: API Manifest Check] → Tool API
                                        ↓
                              [P7: Output Schema Check] → Response
                                        ↓
                              [P4: Hash Chain Logging] → Audit
```

## Properties

| Property | Name | Type | Verified |
|----------|------|------|----------|
| P1 | Authority Monotonic Narrowing | Deterministic | TLA+ |
| P2 | Intent Entailment Preservation | Probabilistic | NLI (88.3% TPR fine-tuned) |
| P3 | Policy Conjunction Preservation | Deterministic | TLA+ |
| P4 | Forensic Reconstructibility | Deterministic | TLA+ |
| P5 | Bounded Cascade Containment | Deterministic | TLA+ |
| P6 | Scope-Action Conformance | Deterministic | TLA+ |
| P7 | Output Schema Conformance | Deterministic | TLA+ |

## Files

### Core System
- `sentinelagent_simulation.py` — IPDP implementation with IntentVerifier, DelegationAuthorityService
- `sentinelagent_das_prototype.py` — Real HTTP DAS with HMAC-SHA256 signing, DelegationBench v4 (516 scenarios)

### Evaluation
- `sentinelagent_llm_agent_eval.py` — 10 LLM-generated multi-step federal workflow scenarios
- `sentinelagent_llm_das_integration.py` — LLM scenarios routed through real DAS HTTP
- `sentinelagent_live_langchain.py` — Live LangChain/GPT-4o-mini integration (requires OPENAI_API_KEY)
- `sentinelagent_redteam.py` — Black-box adversarial red team (30 attacks)
- `sentinelagent_redteam_independent.py` — Independent red team, 7 attack strategies (45 attacks)
- `sentinelagent_robustness.py` — DAS robustness tests (29 edge cases)
- `sentinelagent_theorems.py` — Executable proofs of 5 meta-theorems
- `sentinelagent_nli_finetune.py` — NLI fine-tuning on 190 government delegation examples
- `sentinelagent_fault_tolerance.py` — 2-of-3 threshold signing simulation (9 fault scenarios)

### Formal Verification
- `SentinelAgent.tla` — TLA+ specification of P1, P3–P7
- `SentinelAgent.cfg` — TLC model checker configuration
- `sentinelagent_tla_verify.sh` — Verification script (requires tla2tools.jar)

## Quick Start

```bash
# Install dependencies
pip install -r requirements.txt

# Run DelegationBench v4 (516 scenarios)
python sentinelagent_das_prototype.py

# Run red team evaluation
python sentinelagent_redteam.py

# Run independent red team
python sentinelagent_redteam_independent.py

# Run fault tolerance simulation
python sentinelagent_fault_tolerance.py

# Run NLI fine-tuning (requires ~5 min on CPU)
python sentinelagent_nli_finetune.py

# Run TLA+ verification (requires Java + tla2tools.jar)
bash sentinelagent_tla_verify.sh
```

## Results Summary

| Evaluation | Attacks | TPR | FPR |
|-----------|---------|-----|-----|
| DelegationBench v4 (P2+P6+P7) | 150 | 100% | 0% |
| Black-box red team | 30 | 100% | 0% |
| Independent red team | 45 | 100% | 0% |
| LLM agent (real DAS) | 5 | 100% | 0% |
| DAS robustness | 29 | 100% | — |
| TLA+ model checking | 2.7M states | 0 violations | — |
| Fault tolerance | 9 scenarios | All pass | — |

## Citation

```bibtex
@article{patil2026sentinelagent,
  title={SentinelAgent: Intent-Verified Delegation Chains for Securing Federal Multi-Agent AI Systems},
  author={Patil, KrishnaSaiReddy},
  journal={IEEE Transactions on Dependable and Secure Computing},
  year={2026}
}
```

## Related Work

- [CivicShield](https://github.com/krishnasaireddy/civicshield) — Seven-layer defense for government AI chatbots
- [RAGShield](https://github.com/krishnasaireddy/ragshield) — Provenance-verified defense for government RAG systems

## License

MIT License. See [LICENSE](LICENSE) for details.
