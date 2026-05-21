# Memact Access Notes

Access is the API and gateway layer apps use to access Memact.

It checks apps, API keys, consent, scopes, categories, feature access, capture
event ingestion, and usage logs.

## System Position

```text
Website manages -> Access checks -> Capture records -> Inference understands -> Schema organizes -> Memory stores -> Studio features run -> Apps and users use results
```

Access does not capture activity, infer meaning, form schemas, store memory, or
run Studio features. It verifies whether a request is allowed and routes it.

## Public Copy

Use:

- "Memact helps apps personalize better with context users control."
- "Apps send signals and use features through scoped API access."
- "Users choose what each app can use."

Avoid:

- intent-first positioning
- claims that Access is the meaning engine
- raw-data export framing
