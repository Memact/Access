# Memact description

**Permissioned intent infrastructure for apps.**

```text
Understand what users are trying to do.
```

Memact is infrastructure that helps apps predict user intent from approved digital activity, without giving them raw access to a user's private data.

This repo is the Access layer. It controls app registration, API keys, consent, scopes, activity categories, verification, and revocation.

## System position

```text
Website manages -> Access gates -> Capture records -> Inference understands -> Schema groups -> Intent predicts -> Memory stores -> Apps consume
```

Access decides whether an app is allowed to ask Memact for a scoped operation. It does not infer meaning, form schemas, predict intent, store memory, or expose raw private data.

## What this repo owns

- app registration and API keys
- consent and `connection_id` verification
- scopes, activity categories, revocation, and audit logs
- permission policy compilation and routing
- app-facing verification and gateway endpoints

## What this repo does not own

- capture recording
- semantic understanding
- schema grouping
- intent prediction rules
- memory storage or retrieval logic

## Copy rules

Use:

- "Permissioned intent infrastructure for apps."
- "Understand what users are trying to do."
- "approved digital activity"
- "consent and scope boundaries"
- "API keys identify apps; connection IDs identify user consent"

Avoid:

- generic AI wrapper language
- vague memory-plugin language
- raw-data export framing
- claims that apps get the whole memory graph
- open-source wording unless the repo license explicitly says so
