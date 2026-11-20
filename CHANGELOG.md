# Changelog

## [0.3.0](https://github.com/holbein-io/ephor-scanner/compare/v0.2.0...v0.3.0) (2026-11-19)


### ⚠ BREAKING CHANGES

* the `latest` image tag now points to the latest release instead of the latest build of `main`. Use `edge` (or `sha-<commit>`) to follow `main`. The chart's default image repository changed from `ephor-scanner` to `ghcr.io/holbein-io/ephor-scanner`.

### Features

* automate releases with release-please, sign images and publish the Helm chart ([fc12407](https://github.com/holbein-io/ephor-scanner/commit/fc1240725ae14eb1c1187a13bb7df8e7e8687841))
* **sbom:** generate SBOMs per scanned image and deliver them to Ephor (SBOM_ENABLED, SBOM_FORMAT) ([fc12407](https://github.com/holbein-io/ephor-scanner/commit/fc1240725ae14eb1c1187a13bb7df8e7e8687841))
* **scanner:** support TRIVY_JAVA_DB_REPO and Trivy DB cache settings ([fc12407](https://github.com/holbein-io/ephor-scanner/commit/fc1240725ae14eb1c1187a13bb7df8e7e8687841))


### Bug Fixes

* **scanner:** apply scanner-level Trivy settings and stop TRIVY_* deployment env vars overriding them ([fc12407](https://github.com/holbein-io/ephor-scanner/commit/fc1240725ae14eb1c1187a13bb7df8e7e8687841))
