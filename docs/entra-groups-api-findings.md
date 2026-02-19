# Entra ID Groups API Findings

Captured from live SCA API on 2026-02-19.

## POST /api/access/elevate/groups — Response

**Finding:** Response IS wrapped in a `"response"` key (contrary to initial spec assumption).

```json
{
  "response": {
    "directoryId": "29cb7961-e16d-42c7-8ade-1794bbb76782",
    "csp": "AZURE",
    "results": [
      {
        "sessionId": "93b65b90-8c56-4243-92f5-f1a8b7cd38a6",
        "groupId": "d554b344-5e88-4299-9b5a-11a2b91f19f7"
      }
    ]
  }
}
```

- Fields use **camelCase** (`directoryId`, `sessionId`, `groupId`)
- Response wrapping matches cloud elevation pattern

## GET /api/access/sessions — Group Sessions

**Finding:** Group sessions appear in the standard sessions endpoint with a `target` field.

```json
{
  "response": [
    {
      "session_id": "93510f71-c958-489a-941c-5568bc19d468",
      "user_id": "tim.schindler@cyberark.cloud.40562",
      "csp": "AZURE",
      "workspace_id": "29cb7961-e16d-42c7-8ade-1794bbb76782",
      "session_duration": 3600,
      "target": {
        "id": "d554b344-5e88-4299-9b5a-11a2b91f19f7",
        "type": "groups"
      }
    }
  ],
  "total": 2
}
```

### Key Observations

| Field | Value | Notes |
|-------|-------|-------|
| `target.type` | `"groups"` | Distinguishes from cloud sessions |
| `target.id` | group UUID | Matches `groupId` from eligibility |
| `workspace_id` | directory UUID | Contains the Entra directory ID |
| `role_id` | **absent** | Not present for group sessions |
| `session_duration` | `3600` | Integer seconds, same as cloud |
| `csp` | `"AZURE"` | Always Azure for Entra groups |

### Field Casing

- Session-level fields: **snake_case** (`session_id`, `workspace_id`, `session_duration`)
- Target sub-object fields: **lowercase** (`id`, `type`) — no snake_case or camelCase distinction needed

### Cloud Sessions (for comparison)

Cloud sessions do NOT include a `target` field. The absence of `target` (or `target == nil`) indicates a cloud console session.
