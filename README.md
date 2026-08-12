# cntryl/uno

`uno` copies existing secrets from explicit source references to explicit
destination references. The secret engine is a Go CLI distributed as bundled
native binaries through npm. It never generates secrets and never invokes the
1Password `op` command.

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
   MY_API_KEY=op://$OP_VAULT/my-service/MY_API_KEY -> aws-secrets-manager://$AWS_REGION/my-service/MY_API_KEY
   MY_DATABASE_URL=op://${OP_VAULT}/my-service/MY_DATABASE_URL -> aws-ssm://${AWS_REGION}/my-service/MY_DATABASE_URL
   ```

3. Set every placeholder used by the template, then validate locally. These
   commands do not contact providers and do not write anything:

   ```sh
   export OP_VAULT=my-vault
   export AWS_REGION=us-east-1
   npx uno check
   npx uno sync --dry-run
   ```

4. Choose exactly one execution command:

   | Intent                                | Command                              | Writes remote providers | Writes a local file |
   | ------------------------------------- | ------------------------------------ | ----------------------- | ------------------- |
   | Copy sources to destinations          | `npx uno sync`                       | Yes                     | No                  |
   | Create a development dotenv file      | `npx uno dev`                        | No                      | `.env.secrets`      |
   | Inject secrets into one child process | `npx uno run -- <command> [args...]` | No                      | No                  |

Only `sync` writes destination providers. Do not run it merely to validate a
template. `uno` resolves every source before the first destination write.

## Template contract

Each non-comment line has this exact grammar:

```text
ENV_KEY=<source reference> -> <destination reference>
```

- The left reference is read; the right reference is written.
- `ENV_KEY` names the value in `.env.secrets`, a `run` child environment, and
  command output. It must match `[A-Za-z_][A-Za-z0-9_]*`.
- `$NAME` and `${NAME}` are expanded once from the current environment.
- Blank lines and full-line comments are ignored.
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

`uno run -- <command> [args...]` injects the resolved values only into the child
process, preserves argv and exit status, and does not create a secrets file.

## Provider references

### 1Password

```text
op://vault/item
op://vault/item/field
op://vault/item/path1/path2/field
```

An item-only reference addresses the Secure Note body. Otherwise, the final
segment is a concealed field and intermediate segments form one canonical
section path. Vaults, items, sections, and fields resolve by exact title or ID;
ambiguity fails. Set `OP_SERVICE_ACCOUNT_TOKEN` in CI or `OP_ACCOUNT` for
desktop integration. The service-account token takes precedence.

### AWS Secrets Manager

```text
aws-secrets-manager://region/secret-name
aws-secrets-manager://region/secret-name/key
aws-secrets-manager-arn://$MY_SECRET_ARN
aws-secrets-manager-arn://$MY_SECRET_ARN/key
```

Same-account names use the AWS credential chain. Percent-encode `/` inside a
secret name, for example `my-team%2Fmy-service`. A blob reference addresses the
raw `SecretString`; a keyed reference addresses one top-level JSON string and
preserves sibling properties. Missing destination secrets are created.

For cross-account access, the ARN variable must contain the complete
AWS-generated secret ARN, including its suffix. Configure the resource policy,
caller IAM permission, and KMS access before running `sync`.

### AWS Systems Manager

```text
aws-ssm://region/full/parameter/path
```

This addresses one exact `SecureString`. Writes are deterministic and
sequential; a failure reports mappings completed before the failure.

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
