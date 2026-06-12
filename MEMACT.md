# Memact Access Notes

Access is the API and gateway layer apps use to ask Memact for permissioned work.

It checks apps, API keys, consent, scopes, categories, memory suggestions,
allowed memory reads, and usage logs.

## System Position

```text
App suggests memory or sends app details -> Access checks -> Context organizes -> Yourself shows -> Memory stores accepted entries -> SDK returns allowed memory
```

Access does not decide identity. It verifies whether a request is allowed and
routes it to the right Memact layer.

## Public Copy

Use:

- "See what apps know about you and control it."
- "Apps can suggest memory after consent."
- "Users choose what each app can use."
- "Activity is not identity."

Avoid:

- intent-first positioning
- claims that Access is the meaning engine
- raw-data export framing
- Playground, Capture, or Inference as current core product language
