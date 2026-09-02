# dev-onprem environment

The on-premises half of Mina (ADR-0006): the control-plane API, the management portal and SQL
Server, on the FIAU Proxmox cluster.

Three VMs in a dedicated DMZ VLAN:

| Host | Role | Reachable from |
|---|---|---|
| `mina-dev-cp-proxy` | Publishes the node-facing listener to the internet | Anywhere on 80/443; SSH from corp |
| `mina-dev-cp-app` | Control-plane API and management portal | Node port: the proxy only. Management port and SSH: corp only |
| `mina-dev-cp-sql` | SQL Server | The app host only, on 1433; SSH from corp |

The separation of the two listeners is enforced twice, deliberately. The application refuses a
management request that arrives on the published port (by the local port the connection was
accepted on, not by any header), and the proxy has no server block for the management port at all,
so a mistake in its configuration cannot expose the portal — there is nothing there to expose.

## Credentials

The Proxmox API token is read from the environment and never enters a variable, a tfvars file or
Terraform state:

```bash
export PROXMOX_VE_ENDPOINT="https://pve.fiau.local:8006/"
export PROXMOX_VE_API_TOKEN="terraform@pve!mina=<uuid>"
```

State lives in the same Azure Storage as the Azure environments, so `az login` is still needed —
the state store and the target are different things.

## Apply

```bash
az login                                        # for the state backend only
cp backend.hcl.example backend.hcl              # same storage as dev, key dev-onprem
cp dev-onprem.tfvars.example dev-onprem.auto.tfvars

terraform init -backend-config=backend.hcl
terraform plan -out=onprem.tfplan
terraform apply onprem.tfplan
```

## What this does not do

Provisioning creates the hosts, the accounts, the firewalls and the key-ring directory. It does not:

- **Install SQL Server or onboard Arc** (M4-18). Arc is what makes
  `Authentication=Active Directory Default` work from a Proxmox host, and that single mechanism is
  what keeps SR-005 ("no stored credentials") true for the database. It needs verifying against a
  real Arc-onboarded host rather than assuming.
- **Deploy the application.** The host, the `mina` service account, the firewall and the Data
  Protection key directory are here; the build is a separate step.
- **Obtain a TLS certificate.** nginx is installed and configured but deliberately not started — it
  would restart-loop without a certificate, which is harder to diagnose than a service that is
  plainly not running yet. Install into `/etc/mina/tls`, then `nginx -t && systemctl enable --now
  nginx`.
- **Give you HA.** One of each host. Backup, restore and cluster HA are M4-22 and are the FIAU
  infrastructure team's to design.
