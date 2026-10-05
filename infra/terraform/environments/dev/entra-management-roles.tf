# M3-8: the Mina.TelemetryViewer app role for the browsing-data review view -- an approver-facing
# management-UI screen for reviewing an analyst's C3 hostname telemetry (docs/BACKLOG.md M3-8,
# THREAT_MODEL N10). Deliberately its own role rather than a reuse of Mina.Approver: approving a
# sensitive-session request and reading browsing history are different privileges, and N10's
# purpose-limitation mitigation is weaker if every approver is automatically also a telemetry
# viewer.
#
# Definition only, additive to the "Mina" app registration the same way entra-node-roles.tf's node
# roles are (see that file's header for why this project does not bring the whole application
# under Terraform management). Deliberately no azuread_app_role_assignment here: unlike a node's
# VMSS identity, which has exactly one unambiguous machine assignee this environment already
# knows, which real people get to view browsing data is a governance decision for an owner to make
# in the Entra portal (Enterprise application -> Users and groups) -- the same way Mina.Approver,
# Mina.Analyst and Mina.Admin were assigned when M2-1 created this application out-of-band, not
# something to default to "whoever applies this".
#
# data.azuread_application.mina and data.azuread_service_principal.mina are declared in
# entra-node-roles.tf; Terraform resolves both files as one configuration for this directory, so
# they are referenced here rather than redeclared.

resource "random_uuid" "telemetry_viewer_role" {}

resource "azuread_application_app_role" "telemetry_viewer" {
  application_id       = data.azuread_application.mina.id
  role_id              = random_uuid.telemetry_viewer_role.result
  allowed_member_types = ["User"]
  display_name         = "Mina Telemetry Viewer"
  description          = "Reviews analyst browsing-data (C3 hostname telemetry) in the management UI. Separate from Mina.Approver by design (M3-8)."
  value                = "Mina.TelemetryViewer"
}
