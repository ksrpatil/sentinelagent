--------------------------- MODULE SentinelAgent ---------------------------
(*
  SentinelAgent Formal Specification — TLA+ Mechanized Proofs
  ============================================================
  Formalizes and model-checks properties P1, P3, P4, P5, P6, P7
  of the Delegation Chain Calculus (DCC).
  
  P2 (intent preservation) is probabilistic and cannot be expressed
  in TLA+; it is validated empirically via NLI fine-tuning.
  
  Author: KrishnaSaiReddy Patil
  Date: April 2026
*)

EXTENDS Integers, Sequences, FiniteSets, TLC

CONSTANTS
    Agents,         \* Set of agent identifiers
    Scopes,         \* Set of scope elements
    Policies,       \* Set of policy identifiers
    APIEndpoints,   \* Set of API endpoints
    OutputTags,     \* Set of output tag identifiers
    MaxTokens       \* Maximum number of tokens

VARIABLES
    tokenScope,     \* token_id -> scope (SUBSET Scopes)
    tokenPolicy,    \* token_id -> policies (SUBSET Policies)
    tokenManifest,  \* token_id -> manifest (SUBSET APIEndpoints)
    tokenOutput,    \* token_id -> output schema (SUBSET OutputTags)
    tokenParent,    \* token_id -> parent_id (-1 for root)
    tokenHash,      \* token_id -> hash value (Int)
    tokenRevoked,   \* Set of revoked token IDs
    tokenActive,    \* Set of active (issued) token IDs
    nextId          \* Next token ID to issue

vars == <<tokenScope, tokenPolicy, tokenManifest, tokenOutput,
          tokenParent, tokenHash, tokenRevoked, tokenActive, nextId>>

\* All possible token IDs
TokenIds == 0..MaxTokens-1


(* ================================================================
   INITIAL STATE
   ================================================================ *)

Init ==
    /\ tokenScope = [i \in TokenIds |-> {}]
    /\ tokenPolicy = [i \in TokenIds |-> {}]
    /\ tokenManifest = [i \in TokenIds |-> {}]
    /\ tokenOutput = [i \in TokenIds |-> {}]
    /\ tokenParent = [i \in TokenIds |-> -1]
    /\ tokenHash = [i \in TokenIds |-> 0]
    /\ tokenRevoked = {}
    /\ tokenActive = {}
    /\ nextId = 0

(* ================================================================
   ACTIONS
   ================================================================ *)

\* Issue a root token
IssueRoot(agent, scope, policies, manifest, outSchema) ==
    /\ nextId < MaxTokens
    /\ scope # {}
    /\ scope \subseteq Scopes
    /\ policies \subseteq Policies
    /\ manifest \subseteq APIEndpoints
    /\ outSchema \subseteq OutputTags
    /\ LET id == nextId IN
        /\ tokenScope' = [tokenScope EXCEPT ![id] = scope]
        /\ tokenPolicy' = [tokenPolicy EXCEPT ![id] = policies]
        /\ tokenManifest' = [tokenManifest EXCEPT ![id] = manifest]
        /\ tokenOutput' = [tokenOutput EXCEPT ![id] = outSchema]
        /\ tokenParent' = [tokenParent EXCEPT ![id] = -1]
        /\ tokenHash' = [tokenHash EXCEPT ![id] = id + 1]
        /\ tokenActive' = tokenActive \cup {id}
        /\ tokenRevoked' = tokenRevoked
        /\ nextId' = nextId + 1

\* Delegate: P1 (scope narrowing), P3 (policy conjunction), P6 (manifest), P7 (output)
Delegate(parentId, requestedScope, childManifest, childOutSchema) ==
    /\ parentId \in tokenActive
    /\ parentId \notin tokenRevoked
    /\ nextId < MaxTokens
    /\ requestedScope # {}
    \* P1: Authority Narrowing
    /\ requestedScope \subseteq tokenScope[parentId]
    \* P6: Manifest narrowing
    /\ childManifest \subseteq tokenManifest[parentId]
    \* P7: Output schema narrowing
    /\ childOutSchema \subseteq tokenOutput[parentId]
    /\ LET id == nextId IN
        /\ tokenScope' = [tokenScope EXCEPT ![id] = requestedScope]
        \* P3: Policy Conjunction — child inherits ALL parent policies
        /\ tokenPolicy' = [tokenPolicy EXCEPT ![id] = tokenPolicy[parentId]]
        /\ tokenManifest' = [tokenManifest EXCEPT ![id] = childManifest]
        /\ tokenOutput' = [tokenOutput EXCEPT ![id] = childOutSchema]
        /\ tokenParent' = [tokenParent EXCEPT ![id] = parentId]
        \* P4: Hash chain linkage
        /\ tokenHash' = [tokenHash EXCEPT ![id] = tokenHash[parentId] + id + 1]
        /\ tokenActive' = tokenActive \cup {id}
        /\ tokenRevoked' = tokenRevoked
        /\ nextId' = nextId + 1

\* P5: Cascade revocation — transitive closure
\* Helper: compute all descendants of a token
RECURSIVE Descendants(_, _)
Descendants(tid, active) ==
    LET directChildren == {id \in active : tokenParent[id] = tid}
    IN directChildren \cup UNION {Descendants(c, active) : c \in directChildren}

Revoke(tokenId) ==
    /\ tokenId \in tokenActive
    /\ tokenId \notin tokenRevoked
    \* Revoke this token and ALL descendants (transitive)
    /\ tokenRevoked' = tokenRevoked \cup {tokenId} \cup Descendants(tokenId, tokenActive)
    /\ UNCHANGED <<tokenScope, tokenPolicy, tokenManifest, tokenOutput,
                   tokenParent, tokenHash, tokenActive, nextId>>


(* ================================================================
   NEXT STATE RELATION
   ================================================================ *)

Next ==
    \/ \E a \in Agents, s \in SUBSET Scopes \ {{}}, p \in SUBSET Policies,
          m \in SUBSET APIEndpoints, o \in SUBSET OutputTags :
        IssueRoot(a, s, p, m, o)
    \/ \E pid \in tokenActive, s \in SUBSET Scopes \ {{}},
          m \in SUBSET APIEndpoints, o \in SUBSET OutputTags :
        Delegate(pid, s, m, o)
    \/ \E tid \in tokenActive :
        Revoke(tid)

Spec == Init /\ [][Next]_vars

(* ================================================================
   SAFETY PROPERTIES (INVARIANTS)
   ================================================================ *)

\* P1: Authority Narrowing
\* Every child token's scope is a subset of its parent's scope
P1_AuthorityNarrowing ==
    \A id \in tokenActive :
        tokenParent[id] # -1 =>
            tokenScope[id] \subseteq tokenScope[tokenParent[id]]

\* P3: Policy Conjunction
\* Every child token inherits all parent policies (superset)
P3_PolicyConjunction ==
    \A id \in tokenActive :
        tokenParent[id] # -1 =>
            tokenPolicy[tokenParent[id]] \subseteq tokenPolicy[id]

\* P4: Forensic Reconstructibility
\* Every non-root token has a valid hash chain link to its parent
P4_ForensicReconstructibility ==
    \A id \in tokenActive :
        tokenParent[id] # -1 =>
            /\ tokenParent[id] \in tokenActive
            /\ tokenHash[id] = tokenHash[tokenParent[id]] + id + 1

\* P5: Cascade Containment
\* If a token is revoked, all its descendants are also revoked
P5_CascadeContainment ==
    \A id \in tokenActive :
        id \in tokenRevoked =>
            \A child \in tokenActive :
                tokenParent[child] = id => child \in tokenRevoked

\* P6: Scope-Action Binding (Manifest Narrowing)
\* Every child's manifest is a subset of its parent's manifest
P6_ScopeActionBinding ==
    \A id \in tokenActive :
        tokenParent[id] # -1 =>
            tokenManifest[id] \subseteq tokenManifest[tokenParent[id]]

\* P7: Output Schema Conformance
\* Every child's output schema is a subset of its parent's output schema
P7_OutputSchemaConformance ==
    \A id \in tokenActive :
        tokenParent[id] # -1 =>
            tokenOutput[id] \subseteq tokenOutput[tokenParent[id]]

=============================================================================
