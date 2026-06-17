# Verification Protocol

Every finding must be verified before posting to a PR or presenting to a user as confirmed. This is the single source of truth for verification — [pr-review-handoff.md](pr-review-handoff.md) and [querying.md](querying.md) both link here.

## The checklist

### 1. Confirm the action exists

```bash
iam-validator query action --name <svc:Action>
```

Empty result = action doesn't exist = finding is valid. A non-empty result means the action is real; don't flag it as invalid.

### 2. Confirm condition key support

If the finding suggests adding a condition key:

```bash
iam-validator query action --name <svc:Action> --has-condition-key <key>
```

If the action is absent from results, the key cannot constrain it — the suggestion is wrong for that action. Drop or flag the finding.

### 3. Confirm ARN format

If the finding flags a malformed ARN:

```bash
iam-validator query arn --service <svc> --name <resource-type>
```

Compare the canonical format template against the policy's ARN.

### 4. Confirm wildcard expansion

If the finding is about a wildcard pattern:

```bash
iam-validator query action --name "<svc:Prefix*>"
```

See exactly which actions the wildcard matches. Assess blast radius before reporting severity.

### 5. Drop false positives

If query evidence contradicts the finding, discard or downgrade it. Do not silently drop — tell the user: "The validator flagged X, but `query` shows Y — this appears to be a false positive."

### 6. Deduplicate

Same issue across multiple statements or files = one finding, referencing all locations.

### 7. Sanity-check severity

Keep the validator's severity unless query evidence justifies a change. Don't inflate.

### 8. Record evidence

For each surviving finding, record:

- The query command you ran
- The result (or key excerpt)
- Your verdict: confirmed / downgraded / dropped

This evidence should accompany the finding when handing off for PR review.

## When to skip verification

- **Structural checks** (`policy_structure`, `policy_size`, `sid_uniqueness`) — deterministic; no query needed.
- **Interactive terminal use** — if the user is reviewing findings themselves (not posting to a PR), show findings and let them decide. Offer to verify if asked.

## Quick reference

| Finding type             | Verification command                                                   |
| ------------------------ | ---------------------------------------------------------------------- |
| Action doesn't exist     | `query action --name <svc:Action>`                                     |
| Condition key suggestion | `query action --name <svc:Action> --has-condition-key <key>`           |
| Malformed ARN            | `query arn --service <svc> --name <resource-type>`                     |
| Wildcard blast radius    | `query action --name "<svc:Prefix*>"`                                  |
| Condition key scope      | `query action --service <svc> --has-condition-key <key> --output json` |
