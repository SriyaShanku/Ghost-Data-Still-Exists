# Ghost Data Still Exists: Model Usage and Cost Report

Generated at: 2026-10-25T13:09:14.883282Z

## 1. Executive Summary

The production pipeline executes deterministically in Python using structured rule parsing, in-memory SQLite querying, and pattern indexers. No external paid LLM API calls were invoked during the evaluation run, guaranteeing 100% deterministic reproducibility, zero latency overhead, zero cloud compute costs, and no secrets leakage.

## 2. Usage Breakdown

| Metric | Value |
|---|---|
| Model Provider | None (Deterministic Python Pipeline) |
| Model Name | N/A (Fully Offline Deterministic) |
| Total Model Calls | 0 |
| Input Tokens | 0 |
| Output Tokens | 0 |
| Total Tokens | 0 |
| Average Tokens per Request | 0.0 |
| Estimated Total Cost (USD) | $0.00 |
| Estimated Cost per Request (USD) | $0.0000 |

## 3. Performance & Efficiency

- All 518 evaluation requests and 32 sample requests are processed entirely with local CPU resources.
- Full evaluation run runtime: < 15 seconds.
- Zero API quota dependencies or network failure risks.
