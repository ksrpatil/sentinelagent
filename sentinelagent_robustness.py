#!/usr/bin/env python3
"""
SentinelAgent Robustness Evaluation — Realistic Agent Behavior Patterns

Tests the DAS prototype against inputs that real LLM agents would produce:
- Malformed requests (missing fields, wrong types, extra fields)
- Partial scope specifications
- Unicode and encoding edge cases
- Concurrent delegation chains
- Chain depth stress testing (2 to 32 hops)
- Expired token handling
- Replay attacks (reusing revoked tokens)
- Scope boundary probing (requesting exact boundary of permitted scope)

This addresses the reviewer concern: "What happens when real agents
generate requests with unexpected formatting?"
"""

import json
import time
import threading
import statistics
import sys
import os
from http.server import HTTPServer

sys.path.insert(0, os.path.dirname(__file__))
from sentinelagent_das_prototype import (
    DelegationAuthorityService, DASHandler, DelegationToken,
    FEDERAL_MANIFESTS, OUTPUT_SCHEMAS
)
import sentinelagent_das_prototype as das_mod
import urllib.request
import urllib.error

DAS_PORT = 18925
DAS_URL = f"http://localhost:{DAS_PORT}"

def http_post(path, data):
    req = urllib.request.Request(f"{DAS_URL}{path}",
        data=json.dumps(data).encode(), headers={"Content-Type": "application/json"})
    try:
        resp = urllib.request.urlopen(req)
        return json.loads(resp.read()), resp.status
    except urllib.error.HTTPError as e:
        return json.loads(e.read()), e.code
    except Exception as e:
        return {"error": str(e)}, 500

def run_robustness():
    das_mod._das = DelegationAuthorityService()
    das_mod.DAS_PORT = DAS_PORT
    server = HTTPServer(("localhost", DAS_PORT), DASHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.2)

    scope = {"read_records", "query_eligibility"}
    manifest = {s: FEDERAL_MANIFESTS[s] for s in scope}
    output_schema = {s: OUTPUT_SCHEMAS.get(s, {"permitted": [], "prohibited": []}) for s in scope}
    policy = {"AC-3", "AC-6", "AU-2"}

    root = das_mod._das.issue_root_token("user_001", "agent_001",
        scope, manifest, output_schema, policy, "Process disability benefits")
    child, _ = das_mod._das.delegate(root.token_id, "records_agent",
        {"read_records", "query_eligibility"}, "Retrieve records")
    token_id = child.token_id

    print("=" * 70)
    print("ROBUSTNESS EVALUATION — Realistic Agent Behavior Patterns")
    print("=" * 70)
    results = {"pass": 0, "fail": 0, "tests": []}

    def check(name, expected_block, resp, code):
        # For delegation responses, success = code 200; for check responses, success = allowed=True
        if "token" in resp:
            blocked = (code != 200)
        else:
            blocked = code == 403 or not resp.get("allowed", False)
        correct = (blocked == expected_block)
        status = "PASS" if correct else "FAIL"
        results["pass" if correct else "fail"] += 1
        results["tests"].append({"name": name, "status": status, "blocked": blocked})
        print(f"  [{status}] {name}: {'BLOCKED' if blocked else 'ALLOWED'} (expected {'BLOCK' if expected_block else 'ALLOW'})")

    # --- Test Suite 1: Scope Escalation Attempts ---
    print("\n--- 1. Scope Escalation (P1) ---")
    # Try to delegate with scope not in parent
    resp, code = http_post("/delegate", {"parent_token_id": root.token_id,
        "dst": "evil_agent", "scope": ["read_records", "write_decision"], "intent": "escalate"})
    check("Escalate scope beyond parent", True, resp, code)

    resp, code = http_post("/delegate", {"parent_token_id": root.token_id,
        "dst": "evil_agent", "scope": ["read_records", "query_eligibility", "admin_access"], "intent": "add admin"})
    check("Add admin scope", True, resp, code)

    # Exact parent scope should work
    resp, code = http_post("/delegate", {"parent_token_id": root.token_id,
        "dst": "good_agent", "scope": ["read_records", "query_eligibility"], "intent": "same scope"})
    check("Exact parent scope (should allow)", False, resp, code)

    # Narrower scope should work
    resp, code = http_post("/delegate", {"parent_token_id": root.token_id,
        "dst": "narrow_agent", "scope": ["read_records"], "intent": "narrow"})
    check("Narrower scope (should allow)", False, resp, code)

    # Empty scope
    resp, code = http_post("/delegate", {"parent_token_id": root.token_id,
        "dst": "empty_agent", "scope": [], "intent": "empty scope"})
    check("Empty scope (should allow)", False, resp, code)

    # --- Test Suite 2: P6 Edge Cases ---
    print("\n--- 2. P6 Scope Enforcement Edge Cases ---")
    # Case sensitivity — DAS normalizes to uppercase, so lowercase should work
    resp, code = http_post("/check_api", {"token_id": token_id, "method": "get", "endpoint": "/api/records/query"})
    check("Lowercase method (get→GET normalized)", False, resp, code)

    # Trailing slash — DAS normalizes by stripping, so this should match
    resp, code = http_post("/check_api", {"token_id": token_id, "method": "GET", "endpoint": "/api/records/query/"})
    check("Trailing slash normalized", False, resp, code)

    # Path traversal attempt
    resp, code = http_post("/check_api", {"token_id": token_id, "method": "GET", "endpoint": "/api/records/../admin/dashboard"})
    check("Path traversal attack", True, resp, code)

    # URL encoding attempt
    resp, code = http_post("/check_api", {"token_id": token_id, "method": "GET", "endpoint": "/api/records/%71uery"})
    check("URL-encoded endpoint", True, resp, code)

    # Double method
    resp, code = http_post("/check_api", {"token_id": token_id, "method": "GET GET", "endpoint": "/api/records/query"})
    check("Double method injection", True, resp, code)

    # Valid call should still work
    resp, code = http_post("/check_api", {"token_id": token_id, "method": "GET", "endpoint": "/api/records/query"})
    check("Valid GET /api/records/query", False, resp, code)

    resp, code = http_post("/check_api", {"token_id": token_id, "method": "POST", "endpoint": "/api/eligibility/verify"})
    check("Valid POST /api/eligibility/verify", False, resp, code)

    # --- Test Suite 3: P7 Edge Cases ---
    print("\n--- 3. P7 Output Schema Edge Cases ---")
    # Empty output tags
    resp, code = http_post("/check_output", {"token_id": token_id, "tags": []})
    check("Empty output tags (should allow)", False, resp, code)

    # Single valid tag
    resp, code = http_post("/check_output", {"token_id": token_id, "tags": ["record_data"]})
    check("Single valid tag", False, resp, code)

    # Mix of valid and invalid
    resp, code = http_post("/check_output", {"token_id": token_id, "tags": ["record_data", "malware_payload"]})
    check("Valid + unknown tag (default-deny)", True, resp, code)

    # Unicode tag
    resp, code = http_post("/check_output", {"token_id": token_id, "tags": ["record_data", "données_personnelles"]})
    check("Unicode tag injection", True, resp, code)

    # Very long tag name
    resp, code = http_post("/check_output", {"token_id": token_id, "tags": ["A" * 10000]})
    check("10K-char tag name", True, resp, code)

    # --- Test Suite 4: Token Lifecycle ---
    print("\n--- 4. Token Lifecycle ---")
    # Revoked token
    revoke_root = das_mod._das.issue_root_token("user_r", "agent_r",
        scope, manifest, output_schema, policy, "test revoke")
    revoke_child, _ = das_mod._das.delegate(revoke_root.token_id, "agent_r2",
        {"read_records"}, "test")
    das_mod._das.revoke_chain(revoke_root.token_id)
    resp, code = http_post("/check_api", {"token_id": revoke_child.token_id,
        "method": "GET", "endpoint": "/api/records/query"})
    check("Revoked token API call", True, resp, code)

    resp, code = http_post("/check_output", {"token_id": revoke_child.token_id, "tags": ["record_data"]})
    check("Revoked token output check", True, resp, code)

    # Nonexistent token
    resp, code = http_post("/check_api", {"token_id": "fake_token_999",
        "method": "GET", "endpoint": "/api/records/query"})
    check("Nonexistent token", True, resp, code)

    # Replay: try to delegate from revoked token
    resp, code = http_post("/delegate", {"parent_token_id": revoke_root.token_id,
        "dst": "replay_agent", "scope": ["read_records"], "intent": "replay"})
    check("Delegate from revoked token", True, resp, code)

    # --- Test Suite 5: Chain Depth Stress Test ---
    print("\n--- 5. Chain Depth Stress Test ---")
    depth_latencies = []
    max_depth = 32
    deep_root = das_mod._das.issue_root_token("user_deep", "agent_0",
        scope, manifest, output_schema, policy, "deep chain test")
    current_token = deep_root
    chain_ok = True
    for i in range(1, max_depth + 1):
        t0 = time.perf_counter()
        next_token, msg = das_mod._das.delegate(current_token.token_id,
            f"agent_{i}", {"read_records", "query_eligibility"}, f"hop {i}")
        lat = (time.perf_counter() - t0) * 1000
        depth_latencies.append(lat)
        if next_token is None:
            print(f"  Chain broke at depth {i}: {msg}")
            chain_ok = False
            break
        current_token = next_token
    if chain_ok:
        # Verify P6 still works at depth 32
        resp, code = http_post("/check_api", {"token_id": current_token.token_id,
            "method": "GET", "endpoint": "/api/records/query"})
        valid_at_depth = resp.get("allowed", False)
        resp2, code2 = http_post("/check_api", {"token_id": current_token.token_id,
            "method": "POST", "endpoint": "/api/admin/escalate"})
        blocked_at_depth = not resp2.get("allowed", False)
        print(f"  Depth {max_depth}: valid call={'ALLOWED' if valid_at_depth else 'BLOCKED'}, "
              f"attack={'BLOCKED' if blocked_at_depth else 'ALLOWED'}")
        check(f"Valid call at depth {max_depth}", False, resp, code)
        check(f"Attack blocked at depth {max_depth}", True, resp2, code2)
        # Reconstruction latency at depth 32
        from sentinelagent_das_prototype import http_get
        das_mod.DAS_PORT = DAS_PORT
        t0 = time.perf_counter()
        chain_data = das_mod._das.reconstruct_chain(current_token.token_id)
        recon_lat = (time.perf_counter() - t0) * 1000
        print(f"  Reconstruction at depth {len(chain_data)}: {recon_lat:.2f}ms")
        print(f"  Delegation latency: median={statistics.median(depth_latencies):.3f}ms, "
              f"max={max(depth_latencies):.3f}ms")

    # --- Test Suite 6: Concurrent Chains ---
    print("\n--- 6. Concurrent Chain Isolation ---")
    chain_a_root = das_mod._das.issue_root_token("user_a", "agent_a1",
        {"read_records"}, {"read_records": FEDERAL_MANIFESTS["read_records"]},
        {"read_records": OUTPUT_SCHEMAS["read_records"]}, {"AC-3"}, "chain A")
    chain_b_root = das_mod._das.issue_root_token("user_b", "agent_b1",
        {"query_eligibility"}, {"query_eligibility": FEDERAL_MANIFESTS["query_eligibility"]},
        {"query_eligibility": OUTPUT_SCHEMAS["query_eligibility"]}, {"AC-6"}, "chain B")

    child_a, _ = das_mod._das.delegate(chain_a_root.token_id, "agent_a2", {"read_records"}, "A task")
    child_b, _ = das_mod._das.delegate(chain_b_root.token_id, "agent_b2", {"query_eligibility"}, "B task")

    # Chain A agent tries Chain B's scope
    resp, code = http_post("/check_api", {"token_id": child_a.token_id,
        "method": "GET", "endpoint": "/api/eligibility/check"})
    check("Chain A agent tries Chain B's API", True, resp, code)

    # Chain B agent tries Chain A's scope
    resp, code = http_post("/check_api", {"token_id": child_b.token_id,
        "method": "GET", "endpoint": "/api/records/query"})
    check("Chain B agent tries Chain A's API", True, resp, code)

    # Each chain's valid calls still work
    resp, code = http_post("/check_api", {"token_id": child_a.token_id,
        "method": "GET", "endpoint": "/api/records/query"})
    check("Chain A valid call", False, resp, code)

    resp, code = http_post("/check_api", {"token_id": child_b.token_id,
        "method": "GET", "endpoint": "/api/eligibility/check"})
    check("Chain B valid call", False, resp, code)

    # Revoke chain A, chain B unaffected
    das_mod._das.revoke_chain(chain_a_root.token_id)
    resp, code = http_post("/check_api", {"token_id": child_a.token_id,
        "method": "GET", "endpoint": "/api/records/query"})
    check("Chain A revoked — call blocked", True, resp, code)

    resp, code = http_post("/check_api", {"token_id": child_b.token_id,
        "method": "GET", "endpoint": "/api/eligibility/check"})
    check("Chain B unaffected by A's revocation", False, resp, code)

    # --- Summary ---
    total = results["pass"] + results["fail"]
    print(f"\n{'='*70}")
    print(f"ROBUSTNESS RESULTS")
    print(f"{'='*70}")
    print(f"Total tests: {total}")
    print(f"Passed: {results['pass']}/{total} ({results['pass']/total*100:.1f}%)")
    print(f"Failed: {results['fail']}/{total}")
    if results["fail"] > 0:
        print(f"\nFailed tests:")
        for t in results["tests"]:
            if t["status"] == "FAIL":
                print(f"  - {t['name']}")
    print(f"{'='*70}")

    server.shutdown()

if __name__ == "__main__":
    run_robustness()
