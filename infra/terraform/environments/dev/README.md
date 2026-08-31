# dev environment

One PoC egress stamp (single B2s node, `westeurope`) plus the core resource group. Costs sit
inside the D-04 envelope (`docs/COST_MODEL.md` §3); deallocate the VMSS when idle.

## First-time setup

1. `az login` with the dev subscription; export `ARM_SUBSCRIPTION_ID`.
2. `../../../../scripts/bootstrap-tfstate.sh` once per subscription (creates the state
   storage), then copy `backend.hcl.example` → `backend.hcl` with the printed values.
3. Copy `dev.tfvars.example` → `dev.auto.tfvars` and fill in real values.
4. `terraform init -backend-config=backend.hcl`
5. `terraform plan` — review, then apply.

Plan/apply against the real subscription follows the CLAUDE.md rules: no destructive
operations without explicit human approval.
