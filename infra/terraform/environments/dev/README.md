# dev environment

Two things, in one apply:

- **One PoC egress stamp** in Azure — single B2s node in `westeurope`, behind a load balancer and a
  NAT gateway with a static public prefix. This is the research egress path.
- **The control plane's Azure support resources** — a Key Vault holding the internal CA signing key,
  and a storage account holding audit export anchors. After ADR-0006 these are the *only* Azure
  control-plane resources: the API, the portal, SQL and the service logs run on the FIAU Proxmox
  cluster and are not created here.

Costs sit inside the D-04 envelope (`docs/COST_MODEL.md` §3); deallocate the VMSS when idle.

## What you must supply

| Value | Where | Notes |
|---|---|---|
| Subscription | `ARM_SUBSCRIPTION_ID` or `az account set` | Dev subscription. |
| `tenant_id` | `dev.auto.tfvars` | Entra tenant that owns the Key Vault. |
| `node_image_version` | `dev.auto.tfvars` | Exact Ubuntu 24.04 version. **No default on purpose** — `latest` would make the same configuration produce different nodes (AC-018). List with `az vm image list --publisher Canonical --offer ubuntu-24_04-lts --sku server --all -o table`. |
| `ingress_allowed_cidrs` | `dev.auto.tfvars` | Who may reach the tunnel ingress (D-07). |
| `corp_public_cidrs` | `dev.auto.tfvars` | Organisation public ranges nodes must never reach (AC-017). |
| `control_plane_egress_cidrs` | `dev.auto.tfvars` | Public addresses the Proxmox control plane reaches Azure from. Key Vault and audit storage deny by default and admit only these. |
| `admin_ssh_public_key` | `dev.auto.tfvars` | Node admin access. |

## First-time setup

```bash
az login                                   # dev subscription
export ARM_SUBSCRIPTION_ID=<subscription-guid>

../../../../scripts/bootstrap-tfstate.sh   # once per subscription
cp backend.hcl.example backend.hcl         # fill in the printed storage account name
cp dev.tfvars.example dev.auto.tfvars      # fill in the table above

terraform init -backend-config=backend.hcl
terraform plan -out=dev.tfplan             # review every line before applying
terraform apply dev.tfplan
```

## After the apply

`terraform output` gives the two values the on-premises control plane needs:

- `key_vault_uri` → `Mina:Pki:KeyVaultUri`
- `audit_export_container_uri` → `Mina:Audit:ExportContainerUri`

It also prints `audit_anchors_are_immutable`. **In dev this is `false`, and that is not a
misconfiguration to fix** — the blob immutability policy is `Unlocked` so the environment stays
destroyable, and an unlocked policy can be removed by the same administrator who would be tampering.
It therefore provides no tamper evidence. Production must be `Locked`, which is irreversible for the
retention period; that is a production-gate item, not a default this environment should carry.

The Key Vault SKU is `standard` here (software-protected). The CA signing key warrants `premium` and
its HSM in production.

## Two things a green apply will not give you

1. **The control plane.** It runs on Proxmox and nothing in this repository provisions it yet
   (backlog M6-2). Until it exists the nodes have nothing to fetch an allowlist from and no analyst
   can be issued a session.
2. **A production-capable CA or audit sink.** `M2-2c` (Key Vault-backed CA) and `M6-6` (immutable
   blob audit sink) are unbuilt, so the control plane still refuses to start outside Development
   unless `Mina:AllowDevelopmentFallbacks=true` — which means an ephemeral CA and a filesystem sink.
   The Key Vault and container created here are what those two items will consume.

Plan/apply against the real subscription follows the CLAUDE.md rules: no destructive operations
without explicit human approval.
