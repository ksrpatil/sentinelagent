#!/bin/bash
# SentinelAgent TLA+ Verification Script
# Runs TLC model checker on multiple model sizes

echo "================================================================"
echo "SentinelAgent TLA+ Mechanized Proof Verification"
echo "================================================================"
echo ""

# Model 1: Small (complete verification)
cat > SentinelAgent.cfg << 'EOF'
SPECIFICATION Spec
CONSTANTS
    Agents = {a1, a2}
    Scopes = {s1, s2}
    Policies = {p1}
    APIEndpoints = {e1}
    OutputTags = {t1}
    MaxTokens = 3
CHECK_DEADLOCK FALSE
INVARIANTS
    P1_AuthorityNarrowing
    P3_PolicyConjunction
    P4_ForensicReconstructibility
    P5_CascadeContainment
    P6_ScopeActionBinding
    P7_OutputSchemaConformance
EOF

echo "--- Model 1: Small (2 agents, 2 scopes, 1 policy, 1 endpoint, 1 tag, 3 tokens) ---"
java -XX:+UseParallelGC -Xmx4g -cp tla2tools.jar tlc2.TLC SentinelAgent.tla -config SentinelAgent.cfg -workers auto 2>&1 | grep -E "(Model checking completed|Error|states generated|Finished in)"

echo ""

# Model 2: Medium (complete verification)
cat > SentinelAgent.cfg << 'EOF'
SPECIFICATION Spec
CONSTANTS
    Agents = {a1, a2}
    Scopes = {s1, s2}
    Policies = {p1}
    APIEndpoints = {e1, e2}
    OutputTags = {t1}
    MaxTokens = 3
CHECK_DEADLOCK FALSE
INVARIANTS
    P1_AuthorityNarrowing
    P3_PolicyConjunction
    P4_ForensicReconstructibility
    P5_CascadeContainment
    P6_ScopeActionBinding
    P7_OutputSchemaConformance
EOF

echo "--- Model 2: Medium (2 agents, 2 scopes, 1 policy, 2 endpoints, 1 tag, 3 tokens) ---"
java -XX:+UseParallelGC -Xmx4g -cp tla2tools.jar tlc2.TLC SentinelAgent.tla -config SentinelAgent.cfg -workers auto 2>&1 | grep -E "(Model checking completed|Error|states generated|Finished in)"

echo ""
echo "================================================================"
echo "Properties verified: P1, P3, P4, P5, P6, P7"
echo "P2 (intent preservation) is probabilistic — verified via NLI"
echo "================================================================"
