# Azure Resource Footprint and Cost Model

Status: Phase 0 — **indicative only**. Figures are order-of-magnitude EUR/month at list prices
from public pricing as known at design time; verify with the Azure pricing calculator and the
organisation's agreement before the production go decision (D-11). Prices vary by region.

## 1. Assumptions

- ~50 provisioned analysts, ~25 concurrent typical, browsing-class traffic.
- Data volume: ~300 GB/month internet egress aggregate (browsing, generous).
- MVP: 1 test region; Production proposal: control plane + 2 egress regions.
- Dev/test run scaled-down SKUs and can be deallocated off-hours.

## 2. Production estimate

Per D-11 (2026-08-31) production launches with **one active egress stamp**; the table below
keeps the per-stamp figure so activating further approved regions (D-08) is a known increment.
**Launch envelope: control plane + 1 stamp ≈ €610–1,110/mo**; each additional active region
≈ €240/mo.

| Item | Sizing | Est. €/mo |
|---|---|---|
| App Service plan P1v3 (API + UI) | 1 plan, 2 apps | 110–150 |
| Azure SQL Database GP | 2 vCore provisioned or serverless equivalent | 150–350 |
| Key Vault | standard ops volume | 5–15 |
| Storage (WORM audit + diagnostics) | < 100 GB | 5–15 |
| Log Analytics | ~5–10 GB/day platform logs | 100–300 |
| Telemetry relay | 1 small Container App/VM | 15–40 |
| **Per active egress stamp (×1 at launch):** | | |
| VMSS 2 × D2as_v5 | Envoy nodes | ~140 |
| Standard LB + ingress IP | | ~25 |
| NAT Gateway + /30 IP prefix | resource + 4 IPs | ~55 |
| Data processing (NAT GW + LB) | ~150 GB/stamp | ~10 |
| Internet egress bandwidth | ~150 GB/stamp beyond free tier | ~10 |
| Stamp subtotal | | **~240 each** |
| **Production total (launch, 1 stamp)** | | **≈ €610–1,110 / month** |
| Production with a 2nd active region | | ≈ €850–1,350 / month |

## 3. Non-production

| Environment | Shape | Est. €/mo |
|---|---|---|
| dev | B-series app plan, serverless SQL (auto-pause), 1 × B2s single-node stamp, deallocatable | 80–150 |
| test | production-shaped but 1 region, smaller VMSS | 250–450 |

## 4. Major cost drivers and levers

1. **Log Analytics ingestion** is the most volatile line — cap with sampling/retention tiers;
   security-relevant exports are small.
2. **Azure SQL tier** — serverless with auto-pause suits dev/test; production sizing should
   follow measured telemetry write rates (expected low).
3. **Egress stamps scale linearly per region** — each approved region is ~€240/mo; keep the
   approved list short until demand shows.
4. Bandwidth is negligible at browsing volumes; re-check if usage patterns change (bulk
   downloads, media-heavy research).
5. Not included: Wazuh/SigNoz hosting (existing org services), Intune/Entra licensing
   (existing), penetration-testing engagement (one-off, Phase 4).

## 5. Cost controls

Budgets + alerts per resource group; auto-shutdown schedules in dev; tagging standard
(`mina:env`, `mina:plane`, `mina:region`) enforced via Terraform; monthly cost review in
operations cadence.
