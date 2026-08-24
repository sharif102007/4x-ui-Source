# Build and release 4x-ui

4x-ui is a Go application with embedded web assets. The Linux release bundles
the panel binary, Xray, service units, the CLI, and network helper scripts.

## Local validation

Use the Go version declared in `go.mod` and a C compiler because the SQLite
driver uses CGO.

```bash
gofmt -w .
go vet ./...
go test -race -shuffle=on ./...
go build -o x-ui main.go
```

Before changing an installer or helper script, also run:

```bash
bash -n install.sh update.sh x-ui.sh network-optimize.sh limits-diag.sh 4xui-shaper.sh
```

## GitHub release

`.github/workflows/release.yml` runs formatting, vet, staticcheck, and race
tests first. Only after analysis succeeds does it build the Linux architectures
and Windows package. A version tag such as `v1.1.11` uploads the archives to the
matching GitHub Release.

```bash
git add .
git commit -m "release v1.1.11"
git push origin main
git tag -f v1.1.11
git push origin v1.1.11 --force
```

If a release is being replaced, wait for both `Release 4X-UI` and
`Release 4X-UI for Docker` to finish. Do not publish an archive from a failed
analysis run.

## Linux release contents

The workflow packages these runtime files under `x-ui/`:

- `x-ui` and the architecture-specific Xray binary
- `x-ui.sh`
- `x-ui.service.debian`, `x-ui.service.arch`, and `x-ui.service.rhel`
- `network-optimize.sh`, `limits-diag.sh`, and `4xui-shaper.sh`
- GeoIP and GeoSite databases

HTML, JavaScript, CSS, and the English translation catalog are embedded in the Go binary. The
source screenshots and documentation are for the repository and are not copied
into the runtime release archive.

## Update safety

The updater stops the service before running database migrations or settings
commands, then starts it after configuration and certificate checks finish.
This ordering prevents a panel process and a CLI process from migrating the
same SQLite database at the same time.

## Publish from a VPS clone

No release helper script is bundled. Use your existing authenticated Git/VPS
commands to push the repository and the `v1.1.11` tag. Pushing the tag triggers
the existing binary release workflow and Docker/GHCR workflow.
