# WAF Bypass Detection in Microsoft Sentinel

An operational detection-engineering lab that ingests real ModSecurity/NGINX WAF
logs into **Microsoft Sentinel** and hunts for attacks that **slipped past the WAF**
— suspicious requests that returned `HTTP 200` with **no matching WAF rule hit**.

This is the SIEM follow-on to my MSc dissertation, which empirically evaluated
OWASP CRS Paranoia Levels and documented six attack payloads that evaded detection.
This project takes that same evidence and answers the SOC question: *if the WAF
misses something, can we catch it in the SIEM?*

> **Scope (honest framing):** This is a controlled home-lab on a single-host dataset
> (one origin IP, one target app, ~5,000+ WAF traffic events). It demonstrates the
> detection-engineering workflow — schema design, ingestion, KQL hunting, validation
> against known-bad — not a production deployment or detection tuned on diverse traffic.

---

## What This Demonstrates

- **Log ingestion into Sentinel** via the Azure Monitor **Logs Ingestion API** with
  a purpose-built **Data Collection Rule (DCR)** and two custom tables.
- **Least-privilege cloud identity**: an app registration granted **Monitoring
  Metrics Publisher** scoped *only* to the DCR — no broader subscription access.
- **Detection engineering in KQL**: a `leftanti` join across two log layers
  (what the WAF *caught* vs. what *actually happened*) to surface true bypasses.
- **Validation against ground truth**: the headline rule independently re-discovers
  a boolean-blind SQLi bypass already documented in the dissertation — at **both**
  Paranoia Level 1 and Paranoia Level 2.

---

## Architecture Overview

```
ModSecurity audit log  ─┐
(WAF verdicts: rule IDs, ├─►  Python parser ──►  Azure Monitor          ┌► WAFAudit_CL
 anomaly scores)         │    (flatten to JSON)   Logs Ingestion API ──►│   (what the WAF caught)
                         │                          │  DCR + DCE         │
NGINX access log        ─┘                          │  (app reg w/        └► WAFAccess_CL
(traffic: status,                                   │   Monitoring Metrics    (what actually happened)
 URI, bytes, UA)                                    │   Publisher on DCR)
                                                    ▼
                                          Microsoft Sentinel (Log Analytics)
                                                    │
                                                    ▼
                                          KQL detections / hunting
```

Two custom tables, fed from the dissertation's WAF logs:

| Table | Source log | Represents |
|---|---|---|
| `WAFAudit_CL` | ModSecurity audit (JSON) | **What the WAF caught** — matched rule IDs (`942xxx` SQLi, `941xxx` XSS), rule messages, attack category, paranoia level |
| `WAFAccess_CL` | NGINX access (combined) | **What actually happened** — every request, HTTP status, URI, bytes, user-agent, paranoia level |

**~5,000+ WAF traffic events (attacks and benign)** were ingested in total
(2,520 audit verdicts + 2,492 access events), spanning matched PL1 and PL2 test runs.

See **[ARCHITECTURE.md](ARCHITECTURE.md)** for table schemas, the DCR/DCE, and the
scoped-RBAC ingestion identity ("how it was built").

---

## Detection Approach

The core idea: a WAF bypass is an attack-shaped request that the WAF **let through**.
Each log layer alone can't see it — the audit log only shows what fired, the access
log only shows status codes. Joined, the gap becomes visible.

**[`kql/bypass_detection_leftanti.kql`](kql/bypass_detection_leftanti.kql)** —
the headline hunt:

1. From `WAFAccess_CL`, take requests that returned **`HTTP 200`** and whose
   (URL-decoded) URI matches **SQLi/XSS attack *grammar*** — structural patterns like
   `SELECT ... CASE WHEN`, `<script>`, `onerror=` — deliberately **not** bare keywords,
   so benign text such as *"select your preferred juice flavour"* is not flagged.
2. `join kind=leftanti` against the set of URIs that triggered a real rule in
   `WAFAudit_CL` (`isnotempty(RuleId)`), keyed on URI + paranoia level.
3. What remains = **attack-shaped requests that succeeded with no WAF rule firing** —
   genuine bypasses.

**[`kql/pl1_vs_pl2_comparison.kql`](kql/pl1_vs_pl2_comparison.kql)** —
reproduces the dissertation's *threshold-not-rules* finding directly in Sentinel:
blocked-vs-passed and rule-firing counts split by `ParanoiaLevel`.

---

## Results

- The bypass hunt cleanly isolates the boolean-blind SQLi
  **`1 AND (SELECT CASE WHEN (1=1) THEN 1 ELSE 0 END)=1`**
  (dissertation ID **SQLI_33**) as a `200`/no-rule bypass at **both** PL1 and PL2 —
  matching the dissertation's manually-identified bypass set.
- The PL1-vs-PL2 query shows **more requests blocked at PL2** despite **no
  PL2-specific rules firing** — the extra blocks come solely from the lower anomaly
  threshold (≥3 vs ≥5), the same *threshold-not-rules* effect the dissertation
  quantified.

---

## Screenshots

> Capture these from the Sentinel portal and drop the PNGs into `screenshots/`.

![Bypass detection result](screenshots/bypass-result.png)
![PL1 vs PL2 comparison](screenshots/pl1-vs-pl2.png)

**Shot list — exactly what to capture:**

1. `screenshots/bypass-result.png` — **Logs** blade with
   `bypass_detection_leftanti.kql` run, results grid showing the `SQLI_33`
   `CASE WHEN` row(s) with `StatusCode 200` and both `ParanoiaLevel` values visible.
2. `screenshots/pl1-vs-pl2.png` — results of `pl1_vs_pl2_comparison.kql` showing the
   blocked/passed counts per paranoia level (the threshold effect).
3. `screenshots/custom-tables.png` *(optional)* — the two custom tables
   (`WAFAudit_CL`, `WAFAccess_CL`) listed under the workspace **Tables**.
4. `screenshots/dcr-rbac.png` *(optional)* — the DCR's **Access control (IAM)**
   blade showing the app registration with **Monitoring Metrics Publisher**
   (blur/redact any tenant, subscription, or object IDs).

---

## Related Work

Built on my MSc dissertation — the controlled CRS Paranoia Level evaluation that
produced this dataset and the original "Bypasses Identified" table (incl. SQLI_33):

➡️ **[ModSecurity CRS Paranoia Level Evaluation](https://github.com/Bill-Benson/Modsecurity-crs-paranoia-evaluation)**

---

## Stack

- **SIEM:** Microsoft Sentinel (Log Analytics workspace)
- **Ingestion:** Azure Monitor Logs Ingestion API · Data Collection Rule + Endpoint · Microsoft Entra app registration (scoped Monitoring Metrics Publisher)
- **Query language:** KQL
- **Source data:** OWASP CRS 3.3.8 + ModSecurity v3.0.14 + NGINX WAF logs (from the dissertation testbed)
