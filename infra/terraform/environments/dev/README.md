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
| `mina_app_client_id` | `dev.auto.tfvars` | Client id of the "Mina" Entra app registration (M2-1, created out-of-band). `entra-node-roles.tf` looks it up by this id to add the node app roles (M4-29 item 3); this Terraform never creates or owns the application itself. |
| `node_image_version` | `dev.auto.tfvars` | Exact Ubuntu 24.04 version. **No default on purpose** — `latest` would make the same configuration produce different nodes (AC-018). List with `az vm image list --publisher Canonical --offer ubuntu-24_04-lts --sku server --all -o table`. |
| `ingress_allowed_cidrs` | `dev.auto.tfvars` | Who may reach the tunnel ingress (D-07). |
| `corp_public_cidrs` | `dev.auto.tfvars` | Organisation public ranges nodes must never reach (AC-017). |
| `control_plane_egress_cidrs` | `dev.auto.tfvars` | Public addresses the Proxmox control plane reaches Azure from. Key Vault and audit storage deny by default and admit only these. |
| `control_plane_node_url` | `dev.auto.tfvars` | The published DMZ endpoint every egress node's sidecar calls to admit tunnels (M4-17). **No default on purpose** — since M4-11 a node that can't reach this refuses all research browsing. For dev-onprem: `https://mina-cp.bonnicilabs.com`. |
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

### Bootstrap the internal CA (once per vault)

Terraform creates the signing key but cannot give it a certificate — Key Vault's own certificate
objects are always end-entity, so a CA certificate has to be assembled and signed through the
vault's `sign` operation (D-20). That is one command, run once, by an operator whose account has
the Key Vault Crypto User and Secrets Officer roles this module assigns to the Terraform principal:

```bash
dotnet run --project ../../../../control-plane/tools/Mina.Ca -- bootstrap --vault "$(terraform output -raw key_vault_uri)"
```

Add `--dry-run` to sign a certificate and print it without storing anything — useful to confirm the
vault, the key and the permissions before writing the trust root. `mina-ca show --vault ...` loads
the CA exactly as the control plane does, including the certificate/key match check, so a green
`show` means the API would start on this vault.

The API then needs `Mina:Pki:KeyVaultUri` set and its own identity granted Crypto User and Secrets
User — pass that identity as `control_plane_principal_id`. Here that is the Windows application
host's Arc system-assigned managed identity (`mina-dev-cp-app`, M4-18), the same identity that
already authenticates to SQL Server with no stored credential. A host without that setting still
runs the ephemeral development CA and warns about it at startup.

## Check these two outputs after applying

`audit_anchors_are_immutable` and `alerting_enabled` both report **false** unless you configure
them, and both describe controls that a plan otherwise appears to have. The first is expected in
dev (see above). The second means no alert rules exist: set `alert_email_receivers` if you want to
hear about anything touching the CA vault or the audit anchors — including a delete the immutability
policy refused, which is what an attempt at tampering looks like from outside.

Those alerts fire on your own `terraform apply` too. That is intended rather than noise: these two
resources are meant to be inert after creation, so any ARM operation on them is worth a human
looking, including when it is you.

## Two things a green apply will not give you

1. **The control plane.** It runs on Proxmox and is provisioned separately from `../dev-onprem`
   (M4-15 first cut: hosts, firewalls and the publishing proxy — no SQL Server, Arc onboarding or
   application deployment yet). Until it is up the nodes have nothing to fetch an allowlist from and
   no analyst can be issued a session.
2. **A production-capable audit sink, or a control plane that can reach the CA.** `M4-19` (immutable
   blob audit sink) is unbuilt, so the control plane still refuses to start outside Development
   unless `Mina:AllowDevelopmentFallbacks=true`. The Key Vault CA itself is built (M2-2c) and can be
   bootstrapped here today, but the API can only use it once its host has an identity to grant Key
   Vault roles to — Arc onboarding, M4-18 — so until then it runs the ephemeral CA regardless.

Plan/apply against the real subscription follows the CLAUDE.md rules: no destructive operations
without explicit human approval.
