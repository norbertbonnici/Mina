# Resource Footprint and Cost Model

Status: Phase 0 — **indicative only**, revised 2026-09-02 for ADR-0006. Figures are
order-of-magnitude EUR/month at list prices from public pricing as known at design time; verify with
the Azure pricing calculator and the organisation's agreement before the production go decision
(D-11). Prices vary by region.

Since ADR-0006 the platform is hybrid. **Azure** carries the egress stamps plus two small services
the control plane uses outbound (Key Vault, immutable blob storage) and the Log Analytics workspace
that records their use. **The on-premises Proxmox cluster** carries the control plane — proxy, application
and SQL Server hosts — whose costs are on-premises and not priced here.

## 1. Assumptions

- ~50 provisioned analysts, ~25 concurrent typical, browsing-class traffic.
- Data volume: ~300 GB/month internet egress aggregate (browsing, generous).
- MVP: 1 test region; production launches with 1 active egress stamp (D-11), further approved
  regions (D-08) activated on demand.
- Dev/test run scaled-down SKUs and can be deallocated off-hours.
- Log Analytics ingests Key Vault audit events, anchor-storage access logs and the Entra/Azure
  activity exports for break-glass alerting — a small volume now that no App Service or Azure SQL
  diagnostics flow into it.

## 2. Production estimate (Azure)

Per D-11 (2026-08-31) production launches with **one active egress stamp**; the table keeps the
per-stamp figure so activating further approved regions (D-08) is a known increment.
**Launch envelope, Azure only: ≈ €270–340/mo**; each additional active region ≈ €240/mo. The D-11
figure of €600–1,100/mo predates ADR-0006 and included App Service, Azure SQL and a relay that are no
longer in Azure; the difference has moved to on-premises costs (§3), not disappeared.

| Item | Sizing | Est. €/mo |
|---|---|---|
| Key Vault (premium in production, for the HSM-backed CA key) | standard ops volume | 5–20 |
| Storage (immutable/WORM audit anchors) | < 100 GB | 5–15 |
| Log Analytics | ~0.5–1 GB/day (Key Vault + storage diagnostics, activity export) | 20–60 |
| **Azure control-plane subtotal** | | **≈ 30–95** |
| **Per active egress stamp (×1 at launch):** | | |
| VMSS 2 × D2as_v5 | Envoy nodes | ~140 |
| Standard LB + ingress IP | | ~25 |
| NAT Gateway + /30 IP prefix | resource + 4 IPs | ~55 |
| Data processing (NAT GW + LB) | ~150 GB/stamp | ~10 |
| Internet egress bandwidth | ~150 GB/stamp beyond free tier | ~10 |
| Stamp subtotal | | **~240 each** |
| **Production total, Azure (launch, 1 stamp)** | | **≈ €270–340 / month** |
| Production with a 2nd active region | | ≈ €510–580 / month |

Removed from the Azure bill by ADR-0006: App Service plan P1v3 (€110–150), Azure SQL Database GP
(€150–350), telemetry relay (€15–40), and most of the former Log Analytics volume (€100–300).

## 3. On-premises footprint (on-premises, not priced)

| Item | Sizing (dev today; production to be sized in M4-22) | Cost owner |
|---|---|---|
| Publishing reverse proxy VM | 1 small VM in the DMZ VLAN | On-premises infrastructure |
| Application VM (API + portal) | 1 VM; a second for HA is a design item (ADR-0006, M4-23) | On-premises infrastructure |
| SQL Server VM (Azure Arc-enabled) | 1 VM; **SQL Server licensing** is the material line | On-premises licensing |
| Azure Arc | Arc-enabled server registration is free; Arc-enabled SQL Server billing follows the licence model chosen (pay-as-you-go through Arc, or existing licences) | On-premises licensing |
| Public-CA TLS certificate for the published endpoint | 1 certificate, renewed | Organisation (existing process) |
| Backup, restore, cluster HA, patching, monitoring | Proxmox and SQL Server operations | On-premises operations |

These replace platform-managed availability that App Service and Azure SQL used to provide, and are
the reason M4-22 exists. They should be priced by the organisation's infrastructure team before the production
go decision so that D-11's envelope can be restated as a whole-platform figure.

## 4. Non-production (Azure)

| Environment | Shape | Est. €/mo |
|---|---|---|
| dev | Key Vault (standard) + anchor storage (Unlocked) + Log Analytics, 1 × B2s single-node stamp, deallocatable | 40–90 |
| test | production-shaped Azure side but 1 region, smaller VMSS | 150–300 |

Each also needs a matching on-premises environment (`environments/dev-onprem`; test and prod to
follow), sized by the organisation's infrastructure team. The dev Azure figure sits comfortably inside the D-04
envelope (≤ €150/mo).

## 5. Major cost drivers and levers

1. **Egress stamps scale linearly per region** — each approved region is ~€240/mo and is now the
   dominant Azure line; keep the approved list short until demand shows.
2. **SQL Server licensing on premises** is the material new line and is on-premises; the licence
   model chosen with Arc (M4-18) decides it.
3. **Log Analytics ingestion** is small after ADR-0006 but still the most volatile Azure line —
   keep retention tiers modest; security-relevant exports are small.
4. Bandwidth is negligible at browsing volumes; re-check if usage patterns change (bulk
   downloads, media-heavy research).
5. Not included: Wazuh/SigNoz hosting (existing org services), Intune/Entra licensing
   (existing), Proxmox capacity and operations (§3), penetration-testing engagement (one-off,
   Phase 4).

## 6. Cost controls

Budgets + alerts per resource group; auto-shutdown schedules in dev; tagging standard
(`mina:env`, `mina:plane`, `mina:region`) enforced via Terraform; monthly cost review in
operations cadence, covering the on-premises lines in §3 once priced.
