# Gateway API Conformance

Ferrum tracks Gateway API conformance through the `Gateway API Conformance` GitHub Actions workflow. The workflow installs the upstream Gateway API CRDs, deploys the Ferrum mesh controller into a `kind` cluster using the chart's control-plane RBAC, creates a Ferrum-managed `GatewayClass`, runs the upstream `go test ./conformance -run TestConformance` suite, and uploads the JSON test event stream plus the generated conformance report as workflow artifacts.

## Default run parameters

- Gateway API version: `v1.5.1`
- GatewayClass: `ferrum`
- Controller name: `ferrum.io/gateway-controller`
- Supported features: `Gateway,HTTPRoute`
- Conformance profile: `GATEWAY-HTTP`

## Triggering a run

The workflow is `workflow_dispatch` plus weekly `schedule` (Mondays 07:00 UTC) — no push or pull-request trigger. To kick a run manually:

```bash
gh workflow run "Gateway API Conformance" \
  --field gateway_api_version=v1.5.1 \
  --field supported_features=Gateway,HTTPRoute
```

A `concurrency:` group serialises manual and scheduled runs so they don't race on the same kind cluster name.

## Non-gating today

The workflow is intentionally non-gating while the Gateway API implementation is still converging. A non-zero upstream conformance exit emits a GitHub Actions `::warning::` annotation and is recorded in the uploaded run summary instead of failing the job. Infrastructure failures (control plane never reaches Ready, etc.) still fail the job — only the upstream conformance pass/fail rate is treated as advisory.

## Reading the report

Each run uploads a `gateway-api-conformance-<version>` artifact bundle containing:

| File | What it is |
| --- | --- |
| `gateway-api-conformance-test.json` | Streaming `go test -json` events for every conformance test. |
| `gateway-api-conformance-report.yaml` | Upstream `conformance.gateway.networking.k8s.io/v1alpha1` report. Scroll to `profiles[].coreTests` for pass/fail per test name; failures carry the upstream test description and assertion output. |
| `gateway-api-resources.yaml` | `kubectl get gatewayclasses,gateways,httproutes,grpcroutes -A -o yaml` snapshot. |
| `ferrum-namespace.txt` | `kubectl -n ferrum get all -o wide` snapshot. |
| `ferrum-control-plane.log` | Last 1000 lines of the control-plane container logs. |
| `CONFORMANCE.md` (run-local) | Run metadata, exit code, and artifact pointer summary. |

## Scope

| Surface | Status |
| --- | --- |
| GatewayClass status (`Accepted`, `SupportedVersion`) | Implemented. |
| Gateway top-level status (`Accepted`, `Programmed`, `ResolvedRefs`, `Conflicted`) | Implemented. |
| Gateway listener-level status (`status.listeners[].conditions`, `attachedRoutes`, `supportedKinds`) | Not yet emitted — upstream listener-level conformance assertions will fail. |
| HTTPRoute / GRPCRoute parent status (`Accepted`, `ResolvedRefs`, `Programmed`, `Conflicted`) | Implemented. |
| TLSRoute / TCPRoute status | Watched but not yet emitted. |
| Data-plane request-path conformance (`HTTPRouteSimpleSameNamespace`, `HTTPExactPathMatching`, …) | Workflow only deploys the control plane, so request-routing tests have no listener to dial and will fail until a data plane is also brought up in the test cluster. |

## Condition reasons that diverge from the upstream constants table

Ferrum emits a small set of reasons that are not in the v1 spec's enumerated constants. Custom reasons are permitted by the spec, but tooling that asserts exact upstream strings will see them as unexpected:

| Condition | Ferrum reason | Closest upstream reason | Notes |
| --- | --- | --- | --- |
| Gateway `Programmed=False` | `NoListeners` | `NoResources` / `Pending` | Set when translation accepted the Gateway but produced no materialised listener. |
| Gateway `Programmed=False` / `ResolvedRefs=False` | `TranslationFailed` | `Invalid` | Generic translation error surface. |
| Gateway `Conflicted` (condition type) | n/a | Not in `GatewayConditionType` | Custom Ferrum extension; the upstream constants set is `Accepted` / `Programmed` / `Ready`. |
| Route `Programmed` (condition type) | n/a | Not in `RouteConditionType` | Custom Ferrum extension; the upstream constants set is `Accepted` / `ResolvedRefs` / `PartiallyInvalid`. |
| Route `Accepted=True` + `Programmed=False` | `NoRules` | `Pending` | Set when translation accepted the route but produced no materialised rule. |

These divergences are intentional in the scaffolding phase. They will narrow as Ferrum's coverage of the upstream conditions table grows and the workflow flips to gating.
