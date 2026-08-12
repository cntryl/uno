# Repository guide

`uno` is an idiomatic Go secret-copying engine with a minimal TypeScript npm launcher. Keep one root npm package; `src/` may only select and execute a bundled native binary. Never add install scripts, runtime downloads, shell-mediated execution, source maps, or another package manifest.

Provider adapters implement grouped `ReadMany` and `WriteMany`. Group by provider, region or vault, and secret container. Every source group must resolve before the first write. One container read supplies a consistent snapshot to all of its mappings; clone values for consumers and destroy every secret buffer on success and failure. AWS keyed writes merge once and promote with compare-and-swap retries. 1Password destinations must already exist and be Secure Notes; preserve the fetched item `Version` so the SDK rejects stale writes and retry version conflicts at most three times. SSM remains one operation per exact parameter.

Never log values, environments, SDK objects, resolved references, credentials, or provider error text. Examples and fixtures must use generic placeholders such as `MY_API_KEY`, never real project or organization data.

Before changing behavior, add a focused regression. Run `gofmt`, `go vet ./...`, `go test ./...`, `go test -race ./...`, golangci-lint, govulncheck, `vp check`, `vp test`, `npm audit`, actionlint, and package-manifest/install smoke checks as applicable. Releases require separate proof for the local gates, exact-head hosted CI, tag SHA, registry archive/integrity, clean consumer install, and OIDC trusted-publisher configuration.
