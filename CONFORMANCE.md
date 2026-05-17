# Gateway API Conformance

Ferrum tracks Gateway API conformance through the `Gateway API Conformance` GitHub Actions workflow. The workflow installs the upstream Gateway API CRDs, deploys the Ferrum mesh controller into a `kind` cluster using the chart's control-plane RBAC, creates a Ferrum-managed `GatewayClass`, runs the upstream `go test ./conformance -run TestConformance` suite, and uploads the JSON test event stream plus the generated conformance report as workflow artifacts.

Default run parameters:

- Gateway API version: `v1.5.1`
- GatewayClass: `ferrum`
- Controller name: `ferrum.io/gateway-controller`
- Supported features: `Gateway,HTTPRoute`
- Conformance profile: `GATEWAY-HTTP`

The workflow is intentionally non-gating while the Gateway API implementation is still converging. Its artifact bundle includes `gateway-api-conformance-test.json`, `gateway-api-conformance-report.yaml`, Kubernetes resource dumps, controller logs, and a run-local summary.
