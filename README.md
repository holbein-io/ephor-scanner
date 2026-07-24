# Ephor Scanner

Kubernetes vulnerability scanner agent that discovers running workloads, scans container images with [Trivy](https://github.com/aquasecurity/trivy), and reports findings to the [Ephor](https://github.com/holbein-io/ephor) API.

## How It Works

The scanner runs as a Kubernetes CronJob and executes a stateless 6-phase pipeline on each run:

```
1. Load config        Read environment variables, initialize logging
         |
2. Discover workloads Query K8s API for Deployments, StatefulSets,
         |             DaemonSets, and CronJobs across target namespaces
         |
3. Deduplicate images Extract unique container images across all workloads
         |
4. Scan images        Update Trivy vulnerability DB, then scan all unique
         |             images concurrently (configurable parallelism)
         |
5. Build payloads     Group results by namespace, map to Ephor schema
         |
6. Deliver            POST per-namespace results to /api/v1/scans/ingest
```

Each run generates a scan group ID (UUID) that links all per-namespace payloads together. Failed image scans are logged but do not block delivery of successful results.

## Quick Start

Prerequisites: a Kubernetes cluster with [Helm 3](https://helm.sh/) installed.

```bash
helm install ephor-scanner ./deploy/helm/ephor-scanner \
  --set ephor.apiUrl=http://ephor-api:8080 \
  --set scan.namespaces=default,production
```

The scanner will run on the default schedule (every 6 hours). To trigger an immediate scan:

```bash
kubectl create job --from=cronjob/ephor-scanner ephor-scanner-manual
```

## Configuration

All configuration is via environment variables. When deployed with the Helm chart, these are set through the `values.yaml` file.

### Required

| Variable | Description |
|---|---|
| `EPHOR_API_URL` | Base URL of the Ephor API (e.g., `http://ephor-api:8080`) |
| `SCAN_NAMESPACES` | Comma-separated list of Kubernetes namespaces to scan |

### Optional

| Variable | Default | Description |
|---|---|---|
| `SCAN_CONCURRENCY` | `3` | Number of parallel image scans |
| `SCAN_SEVERITY` | `CRITICAL,HIGH,MEDIUM,LOW` | Severity levels to include |
| `SCAN_WORKLOAD_TYPES` | `Deployment,StatefulSet,DaemonSet,CronJob` | Workload types to discover |
| `EPHOR_AUTH_HEADER` | _(none)_ | Custom authentication header name |
| `EPHOR_AUTH_VALUE` | _(none)_ | Authentication header value |
| `TRIVY_BINARY` | `trivy` | Path to the Trivy executable |
| `TRIVY_CACHE_DIR` | `/tmp/trivy-cache` | Trivy cache directory |
| `TRIVY_CACHE_MODE` | `ephemeral` | Layer cache reuse: `ephemeral` (throwaway per scan), `shared` (reuse layers, forces serial scans), `redis` (reuse layers, keeps concurrency) |
| `TRIVY_CACHE_BACKEND` | _(none)_ | Cache backend URL, required for `TRIVY_CACHE_MODE=redis` (e.g. `redis://ephor-redis:6379`) |
| `TRIVY_TIMEOUT` | `300` | Per-image scan timeout in seconds |
| `TRIVY_DB_UPDATE_TIMEOUT` | `60` | Vulnerability DB update timeout in seconds |
| `TRIVY_DB_REPO` | _(none)_ | Custom OCI repository for the Trivy DB (air-gapped environments) |
| `TRIVY_JAVA_DB_REPO` | _(none)_ | Custom OCI repository for the Trivy Java DB (air-gapped environments) |
| `TRIVY_SKIP_DB_UPDATE` | `false` | Skip DB update if cache is pre-populated |
| `LOG_LEVEL` | `info` | Log level (`debug`, `info`, `warn`, `error`) |
| `LOG_FORMAT` | `json` | Log format (`json` or `text`) |

## Helm Values

Key values for the Helm chart at `deploy/helm/ephor-scanner/`:

| Value | Default | Description |
|---|---|---|
| `schedule` | `0 */6 * * *` | CronJob schedule |
| `ephor.apiUrl` | `""` | Ephor API URL (required) |
| `scan.namespaces` | `""` | Target namespaces (required) |
| `scan.concurrency` | `3` | Parallel image scans |
| `cache.enabled` | `true` | Persist Trivy DB across runs via PVC |
| `cache.size` | `1Gi` | PVC storage size |
| `activeDeadlineSeconds` | `3600` | Maximum job runtime |
| `resources.requests.memory` | `128Mi` | Memory request |
| `resources.limits.memory` | `512Mi` | Memory limit |

See `deploy/helm/ephor-scanner/values.yaml` for the full list of configurable values.

## Development

Prerequisites: Go 1.25+, Make.

```bash
# Build
make build

# Run unit tests
make test

# Run integration tests (requires Trivy binary and network access)
make test-integration

# Lint
make lint

# Format
make fmt
```

The binary is built to `bin/ephor-scanner`. Version is auto-detected from git tags.

### Docker

```bash
docker build -t ephor-scanner .
```

The image is a multi-stage build: Go binary compiled from source, Trivy binary copied from `aquasec/trivy:0.69.3`, both placed on an Alpine 3.21 base. Runs as non-root user (uid 10001).

## Architecture

```
ephor-scanner/
  cmd/scanner/          Entry point (6-phase orchestration)
  config/               Environment variable loading
  internal/
    api/                HTTP client for Ephor API delivery
    discovery/          Kubernetes workload discovery (client-go)
    models/             Data structures matching Ephor API schema
    processor/          Image deduplication, concurrent scanning, payload building
    scanner/            Trivy CLI wrapper (os/exec)
  deploy/helm/          Helm chart (CronJob, RBAC, ConfigMap, Secret, PVC)
  tests/integration/    Integration tests
  docs/adr/             Architecture Decision Records
```

Design decisions are documented in `docs/adr/`. Key choices:

- **Trivy as CLI wrapper** (ADR-001) -- decouples scanner version from Trivy version via stable JSON interface
- **Stateless architecture** (ADR-002) -- no local state, all persistence handled by the Ephor API
- **Direct K8s API discovery** (ADR-003) -- uses client-go for fine-grained workload control
- **CronJob deployment model** (ADR-004) -- resource-efficient batch execution
- **Persistent Trivy cache** (ADR-009) -- PVC avoids re-downloading the vulnerability DB on each run

## Compatibility

Ephor components are versioned independently. Check the [compatibility matrix](https://docs.holbein.io/reference/compatibility) to ensure your scanner, API, and Trivy versions work together.

## Contributing

Contributions are welcome. Please read our [Contributing Guide](CONTRIBUTING.md) for details on the development workflow, commit conventions, and pull request process.

All contributors must sign our [Contributor License Agreement](CLA.md) before their first pull request can be accepted. A GitHub Action will guide you through the process automatically.

## License

This project is licensed under the [GNU Affero General Public License v3.0](LICENSE).
