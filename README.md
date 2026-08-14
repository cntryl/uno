# cntryl/uno

`uno` copies existing secrets from explicit source references to explicit
destination references. The secret engine is a Go CLI distributed as bundled
native binaries through npm. It never generates secrets and never invokes the
1Password `op` command.

## Runtime support

The npm launcher requires Node.js 24.11 or later and bundles binaries for macOS
13.5 or later, Windows 10 or later, and Linux on ARM64 or x64. Linux packages
include separate glibc 2.28 and static musl-compatible binaries; the launcher
selects the matching libc variant without downloading anything at runtime.

1Password desktop-app authentication on Linux requires the glibc variant and a
supported 1Password desktop installation. The musl-compatible binary supports
service-account authentication but not desktop-app authentication.

## Agent quick start

Follow this sequence unless the user explicitly requests something else:

1. Install `uno` without running it:

   ```sh
   npm install --save-dev @cntryl/uno
   ```

2. Create and commit `.env.secrets-template`. Use environment-variable
   placeholders for deployment-specific identifiers. Never put secret values in
   this file.

   ```dotenv
   @runtime=aws-secrets-manager://$AWS_REGION/my-service/runtime

   MY_API_KEY=op://$OP_VAULT/my-service/MY_API_KEY -> @runtime
   MY_DATABASE_URL=op://${OP_VAULT}/my-service/MY_DATABASE_URL -> aws-ssm://${AWS_REGION}/my-service/MY_DATABASE_URL
   ```

3. Set every placeholder used by the template, then validate locally. Use
   `check` for a concise validity summary, or `sync --dry-run` for a
   per-mapping preview of the sync plan. `check` is offline; dry-run resolves
   sources and reads destinations but never confirms or writes:

   ```sh
   export OP_VAULT=my-vault
   export AWS_REGION=us-east-1
   npx uno check
   npx uno sync --dry-run
   ```

4. Choose exactly one execution command:

   | Intent                                   | Command                              | Writes remote providers | Writes a local file |
   | ---------------------------------------- | ------------------------------------ | ----------------------- | ------------------- |
   | Copy sources to destinations             | `npx uno sync`                       | Yes (only what changed) | No                  |
   | Create a development dotenv file         | `npx uno dev`                        | No                      | `.env.secrets`      |
   | Inject secrets into one child process    | `npx uno run -- <command> [args...]` | No                      | No                  |
   | Revert destinations to their prior value | `npx uno rollback`                   | Yes (where supported)   | No                  |

Only `sync` writes destination providers. Do not run it merely to validate a
template. The source-only `dev` and `run` commands do not require variables
used exclusively by destination references or destination aliases. `check`,
`sync`, and `rollback` continue to expand and validate both sides. `uno`
resolves every source before the first destination write.

`sync` diffs each destination's current value against the resolved source
before writing: a destination that already matches is skipped entirely (no
API call, no secret-version churn); one that doesn't exist yet or differs is
a _pending change_. Writing a pending change requires either an interactive
confirmation or `--force` — **in a non-interactive/agent/CI context, pass
`--force` explicitly**, or `sync` refuses with an error rather than hanging
on a prompt. Add `--json` for machine-readable output
(`{"dryRun": false, "changes": [...], "completed": [...]}`). A failed
operation may add a sanitized `error` string. Dry-run uses the same shape with
`dryRun: true` and therefore requires read credentials for every source and
destination.

```sh
npx uno sync --force        # non-interactive: write every pending change
npx uno sync --force --json # same, as structured output for scripts
```

`rollback` reverts every mapping's destination to its previous provider-side
value, one call per distinct container. Support is provider-specific and
reported per mapping rather than assumed:

- **AWS Secrets Manager**: moves `AWSCURRENT` back to `AWSPREVIOUS` — an
  exact, idempotent-to-attempt revert. Fails if there is no distinct previous
  version.
- **AWS SSM**: Parameter Store has no movable "current" pointer, so this
  writes the one-version-back value again as a new version. It is
  best-effort: rolling back twice in a row does not return to the value from
  three writes ago.
- **Azure Key Vault**: copies the immediately prior version's value and
  mutable metadata into a new version. This is best-effort because Key Vault
  has no movable "current" pointer. Rollback requires `get`, `set`, and
  `list` secret permissions.
- **GCP Secret Manager**: reads the numeric version before latest and appends
  its payload as a new version. This is best-effort.
- **HashiCorp Vault KV v2**: uses the engine's native rollback operation.
- **1Password**: not supported yet. Mappings targeting it are reported
  `unsupported`, not silently skipped.

Rollback exits unsuccessfully if any mapping is `failed` or `unsupported`.

Like `sync`, `rollback` requires `--force` in a non-interactive context and
supports `--json`:

```sh
npx uno rollback --force        # non-interactive
npx uno rollback --force --json # {"results":[{"environment":"...","status":"reverted"|"unsupported"|"failed", ...}]}
```

## Template contract

Each non-comment line has this exact grammar:

```text
@ALIAS=<destination reference prefix>
ENV_KEY=<source reference> -> <destination reference>
```

- The left reference is read; the right reference is written.
- `ENV_KEY` names the value in `.env.secrets`, a `run` child environment, and
  command output. It must match `[A-Za-z_][A-Za-z0-9_]*`.
- `$NAME` and `${NAME}` are expanded once from the current environment.
- A named destination alias matches `@[A-Za-z_][A-Za-z0-9_]*` and expands to
  `<destination reference prefix>/<ENV_KEY>`. For example, these mappings
  address two fields in one destination container:

  ```dotenv
  @runtime=aws-secrets-manager://$AWS_REGION/my-service/runtime

  MY_API_KEY=op://$OP_VAULT/my-service/api_key -> @runtime
  MY_DATABASE_URL=op://$OP_VAULT/my-service/database_url -> @runtime
  ```

  Declarations are case-sensitive and must precede their uses. Duplicate,
  undefined, forward-referenced, malformed, chained, and unused aliases are
  rejected. A prefix must not end in `/`. An alias is valid only as the entire
  destination expression; it cannot be a source or be extended as
  `@runtime/OTHER_KEY`. Placeholders in a declaration are expanded once when
  the declaration is parsed.

- An alias always uses `ENV_KEY` as the appended destination segment. Use an
  explicit destination reference when the destination field or parameter name
  must differ.
- Blank lines and full-line comments are ignored.
- A blank or comment-only template is valid and represents zero mappings.
- Missing variables, malformed references, NUL, duplicate environment keys,
  duplicate destinations, and mixed blob/key writes to one container fail
  closed.
- Never log resolved values, child environments, or provider SDK objects.

Use `--template PATH` or set `UNO_TEMPLATE` to select another file. The default
is `.env.secrets-template` in the current working directory.

Provider-sensitive operations have a 60-second deadline by default. Use
`--timeout DURATION` with Go duration syntax (for example, `--timeout 90s` or
`--timeout 2m`) to change it. The deadline covers all of `sync` and `dev`, and
secret resolution for `run`. After `run` resolves its secrets, the child uses
the original parent context and may continue beyond the provider timeout.

## Safe local development

Before `uno dev` contacts a provider, `.gitignore` must effectively ignore both
the destination and its temporary-file namespace:

```gitignore
.env.secrets*
```

If the current directory contains `Dockerfile` or `Dockerfile.*`,
`.dockerignore` must end with the same rule. The destination must also be
untracked and must not be a symlink. `dev` then resolves every source
and atomically replaces `.env.secrets` with a deterministic owner-only (`0600`)
dotenv file. It never writes destination providers.
If the template has no mappings, `uno dev` succeeds without creating or
replacing `.env.secrets`.

`uno run -- <command> [args...]` injects the resolved values only into the child
process, preserves argv and exit status, and does not create a secrets file.
The `--` separator is required so flags intended for the child can never be
interpreted as `uno` flags.
Usage errors exit 2, provider or incomplete-operation failures exit 1, and
successful commands exit 0. `run` preserves the child process exit or signal
code.
The child can read every injected value, and same-user processes may also be
able to inspect its environment through facilities such as
`/proc/<pid>/environ` or `ps e`, depending on the platform and its security
configuration. This is the standard exposure model for environment-variable
injection; use a stronger isolation mechanism when a value must not be exposed
that way.

## Provider references

### 1Password

```text
op://vault/item
op://vault/item/field
op://vault/item/path1/path2/field
op://vault/item?notes
op://vault/item?document
op://vault/item?file=field
op://vault/item?file=path1/path2/field
```

An item-only reference addresses the Secure Note body. Otherwise, the final
segment is a field and intermediate segments form one canonical section path.
Source reads accept both concealed and plain fields; destination writes remain
concealed and destination items must be Secure Notes. Vaults, items, sections,
and fields resolve by exact title or ID; ambiguity fails. Set
`OP_SERVICE_ACCOUNT_TOKEN` in CI or set `OP_ACCOUNT` to the desktop app's
account display name or account UUID (not its sign-in URL). The service-account
token takes precedence.

The source-only `?notes` selector reads the notes text from any item category.
The source-only `?document` selector reads a Document item's contents. The
source-only `?file=` selector reads an attached file, matching its field ID,
file ID, or filename within the selected section. Document and attachment
contents must be UTF-8 text without NUL bytes; binary content is rejected. These
selectors cannot be used as destinations.

A destination alias prefix ends at the item; `ENV_KEY` becomes its field (or
the final field below a section path included in the prefix). Destination items
must already exist and be Secure Notes.

### AWS Secrets Manager

```text
aws-secrets-manager://region/secret-name
aws-secrets-manager://region/secret-name/key
aws-secrets-manager://region/path/to/secret-name/key
aws-secrets-manager-arn://$MY_SECRET_ARN
aws-secrets-manager-arn://$MY_SECRET_ARN/key
```

Same-account names use the AWS credential chain. For keyed references, the
final path segment is the JSON key and every preceding segment after the region
is the secret name. A blob reference addresses the raw `SecretString`; because
it has no key delimiter, percent-encode `/` inside a blob secret name, for
example `my-team%2Fmy-service`. A keyed reference addresses one top-level JSON
string and preserves sibling properties. Missing destination secrets are
created.

For cross-account access, the ARN variable must contain the complete
AWS-generated secret ARN, including its suffix. Configure the resource policy,
caller IAM permission, and KMS access before running `sync`.

A destination alias prefix ends at the secret name or complete ARN;
`ENV_KEY` becomes the top-level JSON key.

### AWS Systems Manager

```text
aws-ssm://region/full/parameter/path
```

This addresses one exact `SecureString`. Writes are deterministic and
sequential; a failure reports mappings completed before the failure.
For a destination alias, `ENV_KEY` is appended to the prefix and becomes part
of the exact parameter path rather than a JSON field.

### HashiCorp Vault (KV v2)

```text
vault://mount/path/to/secret/key
```

The mount is the KV v2 engine's mount point (e.g. `secret`); everything
between it and the final segment is the (possibly multi-segment) secret
path; the last segment is the field name. Uses the standard `VAULT_ADDR` and
`VAULT_TOKEN` environment variables. Writes merge into the existing document
and use the KV v2 engine's native check-and-set option, retried on conflict.
A destination alias prefix ends at the secret path; `ENV_KEY` becomes the KV
v2 document field.

### GCP Secret Manager

```text
gcp-secret-manager://project/secret-name
gcp-secret-manager://project/secret-name/key
```

Uses Application Default Credentials (`GOOGLE_APPLICATION_CREDENTIALS`, a
service account attached to the runtime, or `gcloud auth
application-default login`). A blob reference addresses the raw secret
payload; a keyed reference addresses one top-level JSON field and preserves
siblings. Missing destination secrets are created. Unlike AWS Secrets
Manager and Vault, the stable API has no compare-and-swap primitive for
writes — a racing concurrent writer can still clobber a merge.
A destination alias prefix ends at the secret name; `ENV_KEY` becomes the
top-level JSON key.

### Azure Key Vault

```text
azure-key-vault://myvault.vault.azure.net/secret-name
azure-key-vault://myvault.vault.azure.net/secret-name/key
```

References require the full canonical vault hostname. Public Azure
(`vault.azure.net`), US Government (`vault.usgovcloudapi.net`), China
(`vault.azure.cn`), and Germany (`vault.microsoftazure.de`) domains are
accepted. Authentication uses `DefaultAzureCredential`; the identity needs
`get` and `set` secret permissions, plus `list` for rollback.

A blob reference reads or writes the whole value. A keyed reference treats
the latest value as a top-level JSON object, preserves sibling properties,
and preserves content type, tags, enabled state, not-before, and expiry when
creating the replacement version. A missing destination secret starts as an
empty JSON object. Azure Key Vault has no conditional value-write primitive,
so concurrent keyed read-modify-write operations can lose an intervening
sibling update. Uno does not retry an ambiguous `SetSecret` failure because
that could create duplicate versions.
A destination alias prefix ends at the secret name; `ENV_KEY` becomes the
top-level JSON key.

## Repository development

Run all project gates from the repository root:

```sh
gofmt -w ./cmd ./internal
go vet ./...
golangci-lint config verify
golangci-lint run ./...
go test ./...
vp install --frozen-lockfile
vp check
vp test
vp pack
```

The Vite+-built TypeScript launcher selects a bundled native binary for the
current platform. Installation never downloads or executes a binary.
