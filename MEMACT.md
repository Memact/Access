# Memact Access Notes

Access is the API and gateway layer apps use to access Memact.

It checks apps, API keys, consent, scopes, categories, feature access, capture
event ingestion, and usage logs.

## System Position

```text
Website manages -> Access checks -> Capture records -> Inference understands -> Schema organizes -> Memory stores -> Playground features run -> Apps and users use results
```

Access does not capture activity, infer meaning, form schemas, or store memory.
It verifies whether a request is allowed, routes it, and can run Playground features
when the Playground runtime is connected.

## Public Copy

Use:

- "Memact is a playground where apps personalize around what users choose."
- "Apps send signals and use features through scoped API access."
- "Users choose what each app can use."

Avoid:

- intent-first positioning
- claims that Access is the meaning engine
- raw-data export framing
