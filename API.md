# Memact Developer API Reference

This document outlines the core HTTP endpoints exposed by the Memact API Gateway (`Access`). External applications and agents use these endpoints to authorize access, request user context packets, propose suggestions, and rectify existing records.

---

## 1. Authentication & Headers

All requests to the Memact API Gateway must include the private API key in the `Authorization` header. If a request is acting on behalf of a specific user connection, the corresponding connection ID must be passed in the custom header.

### Required Headers
*   `Authorization: Bearer <your_app_api_key>`
*   `Content-Type: application/json`
*   `x-memact-connection-id: <user_connection_id>` (Required for all user-scoped data requests)

---

## 2. Endpoints Reference

### 🌐 Discover Policy & Capabilities
Discover supported categories, safety rules, and scopes on this gateway.

*   **URL:** `GET /v1/policy`
*   **Authentication:** Not required (public endpoint)
*   **Response (200 OK):**
    ```json
    {
      "activity_categories": {
        "shopping": { "description": "User shopping preferences and sizes" },
        "fitness": { "description": "Workouts, daily goals, and sports" }
      },
      "safety_rules": [
        "Never store raw credentials or raw location data."
      ]
    }
    ```

---

### 🔑 Context Access Protocol (CAP) Request
Request a task-specific, user-authorized context packet. Memact filters the response based on the scopes you have been granted.

*   **URL:** `POST /v1/cap/request`
*   **Headers:** Requires `Authorization` and `x-memact-connection-id`.
*   **Request Body:**
    ```json
    {
      "app_id": "my-client-app",
      "connection_id": "conn_abc123",
      "purpose": "onboarding_personalization",
      "requested_categories": ["shopping"],
      "requested_context": [
        { "description": "shoe size", "required": true },
        { "description": "preferred brands", "required": false }
      ]
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "request_id": "cap_req_987",
      "allowed_context": [
        {
          "field_path": "shopping.shoe_size",
          "value": "10.5",
          "category": "shopping",
          "sensitivity": "low"
        }
      ],
      "missing_context": [
        {
          "description": "preferred brands",
          "reason": "no_durable_value_found"
        }
      ]
    }
    ```

---

### 📥 Context Contribution Protocol (CCP) Proposal
Propose new context observations or raw evidence back to the user's registry. Proposals go to the user's **Suggestions** queue for review before becoming durable memory.

*   **URL:** `POST /v1/contributions/propose`
*   **Headers:** Requires `Authorization` and `x-memact-connection-id`.
*   **Request Body (Structured Context Proposal):**
    ```json
    {
      "app_id": "my-client-app",
      "category": "fitness",
      "field_path": "fitness.stable_preferences.favorite_sports",
      "value": ["running"],
      "evidence": {
        "source_summary": "User completed 3 runs this week on client-app.",
        "confidence": 0.85
      }
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "proposal_id": "prop_xyz789",
      "status": "pending_user_review",
      "credit_earned": 5.0
    }
    ```

---

### 🔄 Context Rectification Protocol (CRP)
Propose a correction, deletion, or request that the gateway forget a specific context entry.

*   **URL:** `POST /v1/contributions/rectify`
*   **Headers:** Requires `Authorization` and `x-memact-connection-id`.
*   **Request Body (Forget Request):**
    ```json
    {
      "app_id": "my-client-app",
      "action": "forget",
      "field_path": "shopping.shoe_size",
      "reason": "User requested size preference deletion inside client-app UI."
    }
    ```
*   **Response (200 OK):**
    ```json
    {
      "status": "rectification_queued",
      "details": "Forget request forwarded to user Yourself Suggestions."
    }
    ```

---

### 💳 Check Developer Credits
Check your app's current API read/write credits balance.

*   **URL:** `GET /v1/credits`
*   **Headers:** Requires `Authorization`.
*   **Response (200 OK):**
    ```json
    {
      "app_id": "my-client-app",
      "credits_balance": 245.50,
      "tier": "developer_standard"
    }
    ```
