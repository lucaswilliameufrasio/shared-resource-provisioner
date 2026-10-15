# Contributor guidance

- Keep this repository independent of Uirapuru; do not call its API, MCP, SDK,
  or lifecycle.
- This is a resource-provisioning control plane, not a SQL query gateway. MCP
  operations must be typed business actions; never expose arbitrary SQL,
  shell, Docker, or provider passthrough tools.
- Never return credential values to MCP callers or include them in logs,
  errors, audit events, examples, or tests. Return secret references only.
- Keep authorization deny-by-default and audit state-changing operations.
- Before changing a capability or service boundary, read
  `docs/architecture.md` and the relevant ADRs.
- Follow `TESTING_STANDARD.md`. Run tests only against isolated local test
  resources; do not use production or shared service endpoints.
