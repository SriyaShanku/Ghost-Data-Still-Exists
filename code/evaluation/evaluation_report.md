# Ghost Data Still Exists: Evaluation Report

Generated at: 2026-10-25T13:09:14.882632Z

## 1. Summary Metrics

- **Total Sample Cases Evaluated:** 32
- **Case-Level Deletion-Status Accuracy:** 75.00% (24/32)
- **Step-Level Precision:** 81.06%
- **Step-Level Recall:** 55.44%
- **Step-Level F1 Score:** 65.85%
- **Exact Sequence Accuracy:** 12.50%
- **Average LCS Sequence Match Ratio:** 46.78%

### Confusion Matrix (Case Status)

| Ground Truth \ Predicted | COMPLETE | INCOMPLETE | NOT_APPLICABLE |
|---|---|---|---|
| **COMPLETE** | 10 | 0 | 0 |
| **INCOMPLETE** | 8 | 14 | 0 |
| **NOT_APPLICABLE** | 0 | 0 | 0 |

### Field-Level Accuracy

| Field | Accuracy |
|---|---|
| `phase` | 84.62% |
| `system_id` | 72.31% |
| `resource_id` | 62.31% |
| `operation` | 70.00% |
| `state` | 74.62% |
| `evidence_id` | 89.23% |

## 2. Custom Evaluation Test Cases

### Custom Case 1: Historical Email Request Resolution

A user requests deletion citing a historical email that was changed 1 year ago in user_audit_log.csv. The agent must resolve the stable user_id, search the current snapshot and secondary records, and verify that both old and current email occurrences are audited.

- **Expected Deletion Status:** `INCOMPLETE`
- **Rationale:** Historical email belongs to user_10. Unredacted PII remains in support replica log evidence_61.

### Custom Case 2: Explicit Non-Deletion Request (Intent Check)

A user requests export of personal data in a portable format and asks to leave the account active.

- **Expected Deletion Status:** `NOT_APPLICABLE`
- **Rationale:** Request is for portability/export, not deletion. Output must be NOT_APPLICABLE with steps_json=[].

### Custom Case 3: Post-audit_at Evidence Cutoff & Tombstone Preservation

Evidence is present after audit_at that changes record state, but cutoff at audit_at strictly ignores it; tombstone retains user_id while verifying name/email/phone/hash redaction.

- **Expected Deletion Status:** `COMPLETE`
- **Rationale:** Tombstone tombstone_440 preserves stable internal user_id while name, email, phone, and hash are redacted as verified in evidence_51.

## 3. Failures Found and Improvements Made

- **Historical Identity Resolution:** Resolved multiple cases where users submitted requests using older emails recorded only in `user_audit_log.csv`. Added full historical tracking to `IdentityResolver`.
- **Time-Bounded Evidence Cutoff:** Enforced strict filtering at `audit_at`. Records or snapshots captured after `audit_at` are ignored.
- **Tombstone Redaction Rules:** Distinguished between compliant tombstones (where only stable internal `user_id` is preserved and direct PII is null) versus exposed tombstones.
- **Multi-Phase Ordering & Deterministic Output:** Ensured exact ordering `FINDING` -> `REMEDIATION` -> `VERIFICATION`, sorting by operation priority, `system_id`, and `resource_id`.
