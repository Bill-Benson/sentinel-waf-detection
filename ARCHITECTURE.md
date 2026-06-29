# Architecture — How It Was Built

End-to-end pipeline that takes the dissertation's WAF logs and makes them
queryable as detection data in Microsoft Sentinel.

> All tenant/subscription/resource identifiers below are shown as **placeholders**
> (`<TENANT_ID>`, `<DCE_ENDPOINT>`, `<DCR_IMMUTABLE_ID>`, …). The real values live
> only in local environment variables and are never committed.

---

## 1. Source data

Two log files per Paranoia Level run, from the dissertation testbed
(ModSecurity v3.0.14 + NGINX + OWASP CRS 3.3.8 in front of OWASP Juice Shop):

- **ModSecurity audit log** (JSON-per-line) — one object per transaction, including
  matched rules (`messages[].details.ruleId`), rule messages, tags, and anomaly score.
- **NGINX access log** (combined format) — one line per request: client IP, method,
  URI, HTTP status, bytes, user-agent.

A Python step flattens each into rows matching the target table schemas, tagging
every row with its source `ParanoiaLevel` (1 or 2).

---

## 2. Custom tables (schemas)

### `WAFAudit_CL` — what the WAF caught

| Column | Type | Notes |
|---|---|---|
| `TimeGenerated` | datetime | ISO-8601 UTC |
| `ClientIP` | string | source IP |
| `RequestMethod` | string | HTTP method |
| `RequestURI` | string | request path + query (percent-encoded) |
| `RuleId` | string | first matched CRS attack rule (`942xxx`=SQLi, `941xxx`=XSS); empty if none fired |
| `RuleMessage` | string | human-readable rule message |
| `AttackCategory` | string | `SQLi` / `XSS` / `Other` (derived from `RuleId`) |
| `ParanoiaLevel` | int | source run: `1` or `2` |

### `WAFAccess_CL` — what actually happened

| Column | Type | Notes |
|---|---|---|
| `TimeGenerated` | datetime | ISO-8601 UTC |
| `ClientIP` | string | source IP |
| `RequestMethod` | string | HTTP method |
| `RequestURI` | string | request path + query (percent-encoded) |
| `StatusCode` | int | HTTP response status |
| `BytesSent` | int | response body bytes |
| `UserAgent` | string | client UA |
| `ParanoiaLevel` | int | source run: `1` or `2` |

---

## 3. Ingestion pipeline (Logs Ingestion API)

```
local JSON rows ──► POST ──► Data Collection Endpoint (DCE)
                              └─► Data Collection Rule (DCR)
                                    ├─ stream Custom-WAFAudit_CL  ──► WAFAudit_CL
                                    └─ stream Custom-WAFAccess_CL ──► WAFAccess_CL
```

- **Data Collection Endpoint (DCE):** `<DCE_ENDPOINT>` — the regional ingestion URL.
- **Data Collection Rule (DCR):** `<DCR_IMMUTABLE_ID>` — declares the two input
  streams (`Custom-WAFAudit_CL`, `Custom-WAFAccess_CL`) and routes each to its table.
- **Auth:** OAuth2 client-credentials against Microsoft Entra, scope
  `https://monitor.azure.com/.default`, using the `azure-identity` +
  `azure-monitor-ingestion` SDK (`ClientSecretCredential` + `LogsIngestionClient`).
- Rows are batched (≤500/call, SDK also chunks to the API's ~1 MB limit).

**Volume ingested:** ~5,000+ WAF traffic events total — **2,520** audit verdicts
(`WAFAudit_CL`) + **2,492** access events (`WAFAccess_CL`) — across matched PL1/PL2 runs.

---

## 4. Least-privilege ingestion identity (scoped RBAC)

- A **Microsoft Entra app registration** acts as the ingestion principal
  (client ID `<CLIENT_ID>`, tenant `<TENANT_ID>`).
- It is granted the **Monitoring Metrics Publisher** role **only on the DCR**
  (`<DCR_IMMUTABLE_ID>`) — *not* at subscription or resource-group scope. The
  identity can publish to this one rule and nothing else.
- The client secret is supplied at runtime via environment variables and is never
  stored in code or committed:

```bash
# environment only — never hardcode / never commit
AZURE_TENANT_ID=<TENANT_ID>
AZURE_CLIENT_ID=<CLIENT_ID>
AZURE_CLIENT_SECRET=<CLIENT_SECRET>

# non-secret config passed to the uploader
DCE_ENDPOINT=<DCE_ENDPOINT>
DCR_IMMUTABLE_ID=<DCR_IMMUTABLE_ID>
AUDIT_STREAM=Custom-WAFAudit_CL
ACCESS_STREAM=Custom-WAFAccess_CL
```

---

## 5. Detection layer

KQL detections run over the two tables — see [`kql/`](kql/). The headline rule
(`bypass_detection_leftanti.kql`) `leftanti`-joins access traffic against the set of
URIs that triggered a WAF rule, isolating attack-shaped `200`s with no verdict
(true bypasses). `pl1_vs_pl2_comparison.kql` reproduces the dissertation's
threshold-not-rules result.

---

## Limitations

- Single source IP, single target application, replayed test traffic — **not**
  representative production telemetry. The bypass regex is tuned to this payload set.
- Designed to demonstrate the **method** (schema → ingestion → KQL → validation),
  not to ship a generalised production detection.
