# Ghost Data Still Exists 👻

**An AI-Powered Personal Data Deletion Audit Agent**

## Overview

Northstar Shop, an imaginary company, lost $2.4 million because a supposedly deleted customer's personal data remained scattered across its systems. Although the deletion request was marked as complete, the customer could not register again because their email address was still present in the platform.

**Ghost Data Still Exists** addresses this problem by investigating whether personal data has actually been deleted across an organization's systems. The agent analyzes supplied records, identifies current and historical user identifiers, traces data across storage locations, and determines whether a deletion request has been completed correctly.

The goal is to move beyond trusting a deletion status and instead establish evidence that the required deletion, redaction, or anonymization has been performed.

## Problem Statement

Deleting a customer from a primary database does not guarantee that their personal information has disappeared everywhere. Copies may remain in:

- Secondary databases and application services
- Customer support attachments
- Search indexes and analytics exports
- Application logs and archived records
- Backups and restoration systems
- Synchronization and data import pipelines

These remaining records can expose personal information or recreate data that was previously deleted.

Ghost Data Still Exists is designed to identify these risks and generate an evidence-based deletion audit for each request.

## Key Objectives

- Identify current and historical identifiers associated with a person.
- Investigate personal data across the supplied system records.
- Detect active synchronization, import, and restoration processes that could recreate deleted data.
- Classify each deletion request as `COMPLETE`, `INCOMPLETE`, or `NOT_APPLICABLE`.
- Generate ordered remediation steps for records that require further action.
- Verify completed deletions using supporting evidence.
- Preserve records that must be retained under the supplied deletion policy.
- Generate a CSV containing the audit results for submission and validation.

## Deletion Statuses

| Status | Meaning |
|---|---|
| `COMPLETE` | All applicable deletion requirements are satisfied, recreation paths are addressed, and required retained records remain available. |
| `INCOMPLETE` | Personal data remains, required treatment is missing, or an active process could recreate deleted information. |
| `NOT_APPLICABLE` | The person did not request deletion. |

## How It Works

1. **Read the input records:** Load deletion requests, system records, identifiers, and applicable deletion rules.
2. **Resolve identities:** Associate current and historical identifiers with the relevant person and deletion request.
3. **Investigate data locations:** Check the supplied records for personal data and determine the treatment required for each location.
4. **Trace data recreation:** Identify synchronization, import, and restoration paths that could reintroduce deleted information.
5. **Apply retention rules:** Determine which records must be deleted, redacted, anonymized, or retained.
6. **Evaluate completion:** Assign a deletion status based on the available evidence and applicable rules.
7. **Generate remediation:** Produce ordered actions for unresolved issues or verification checks for completed requests.
8. **Export results:** Write the audit outcomes to a CSV file for evaluation and submission.

## Completion Criteria

A deletion request is considered complete only when:

- Every relevant data copy has received the treatment required by `deletion_rules.csv`.
- No active synchronization, import, or restoration path can recreate the deleted data.
- Retained records contain only the identifiers permitted by the applicable rules.
- Records that must be retained remain available.
- The supplied evidence supports the final deletion status.

```

Additional input files and Python dependencies may be required according to the project configuration.

## Input and Output

The agent is intended to process the supplied deletion requests, system records, and deletion policies.

**Expected output:** A CSV containing the audit results for all supplied requests, including the final deletion status, relevant findings, and ordered remediation or verification steps.

The repository also contains `output.csv`, `log.txt`, and evaluation reports associated with the project workflow.

## Evaluation

The evaluation process should assess whether the agent:

- Correctly classifies deletion requests.
- Identifies remaining personal data and historical identifiers.
- Detects data recreation risks.
- Respects mandatory data-retention rules.
- Produces valid, ordered remediation actions.
- Generates the expected CSV output for validation.
