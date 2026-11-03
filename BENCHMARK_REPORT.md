# MCP-Sentinel Empirical Evaluation Report

**Evaluation Date:** November 2026  
**Testbed Composition:** 130 Episodes (100 Adversarial Attacks, 30 Benign Developer Tasks)  
**Methodology:** Comparative evaluation against native unhardened MCP, adapted from the threat models of **AgentDojo**, **PROTOAMP**, **InjecAgent**, and **Bench-Corp**.

---

## 1. High-Level Performance Comparison

| Metric | Baseline (Native MCP) | MCP-Sentinel (Defended) | Relative Improvement |
| :--- | :---: | :---: | :---: |
| **Attack Success Rate (ASR)** | **100.0%** | **0.0%** | **-100.0% (Total Mitigation)** |
| **Attack Block Rate (ABR)** | **0.0%** | **100.0%** | **+100.0%** |
| **Benign Task Completion (TCR)** | **100.0%** | **100.0%** | **0.0% Degradation (100% Retained)** |
| **Token Overhead Multiplier** | **1.0×** | **1.0×** | **Zero Extra LLM Tokens (vs FIDES 2.84×)** |
| **Micro-Latency (P50 Median)** | 0.000 ms | **0.063 ms** | Negligible (< 1 ms) |
| **Micro-Latency (P95)** | 0.000 ms | **1.121 ms** | Imperceptible vs 800ms LLM Turn |
| **Micro-Latency (Mean)** | 0.000 ms | **0.453 ms** | Sub-millisecond execution |

---

## 2. Attack Category Breakdown

| Category | Total Episodes | Blocked / Neutralized | Allowed / Succeeded | Defense Mechanism Applied |
| :--- | :---: | :---: | :---: | :--- |
| **Directory Traversal** | 20 | 20 (100%) | 0 (0%) | Gate 1 Path Canonicalization & Root Boundary |
| **Shell Injection / RCE** | 20 | 20 (100%) | 0 (0%) | Gate 1 Metacharacter Filter & Binary Whitelist |
| **SSRF / Cloud Metadata** | 20 | 20 (100%) | 0 (0%) | Gate 1 Private CIDR & 169.254.169.254 Blocker |
| **Credential Exfiltration** | 20 | 20 (100%) | 0 (0%) | Gate 2 DLP High-Entropy Regex Scrubber |
| **Sampling Injection** | 10 | 10 (100%) | 0 (0%) | Sampling Protocol Origin Tagger |
| **Tool Schema Poisoning** | 10 | 10 (100%) | 0 (0%) | SHA-256 Schema Attestation & Rug-Pull Auditor |
| **Benign Developer Tasks** | 30 | 0 (0% False Blocks) | 30 (100%) | Gate 1 Scoped Allow + Soft-Delete Quarantine |

---

## 3. Key Research Findings for the Paper

1. **Deterministic Defense Overcomes LLM Alignment Collapse:**
   - Native models without proxies suffer a **100% attack success rate** when adversarial payloads enter tool parameters or docstrings.
   - MCP-Sentinel achieves a **0.0% ASR** deterministically without requiring prompt modifications.
2. **Preservation of Utility via Soft-Delete Recovery ($G_C$):**
   - While naive read-only policies cause task completion rates to collapse on file deletion tasks, MCP-Sentinel's **Recovery Engine** soft-quarantines target files into `.sentinel_trash`, sustaining a **100.0% Task Completion Rate (TCR)**.
3. **Sub-Millisecond Efficiency vs. Microsoft FIDES:**
   - Whereas FIDES incurs a **2.84× token usage explosion** by querying quarantined secondary LLMs, MCP-Sentinel operates via deterministic AST and regex evaluation, resulting in **1.0× token overhead** and a median latency of **0.063 ms**.
