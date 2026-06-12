# compat-opentofu

OpenTofu compatibility tests for [floci-ctf](https://github.com/kangwijen/floci-ctf). Same coverage as `compat-terraform`, using the OpenTofu CLI.

## Running

```bash
# From compatibility-tests/
just test-opentofu

# Or directly
./compat-opentofu/run.sh
```

## Configuration

Bats helpers source [`../lib/ctf-env.sh`](../lib/ctf-env.sh). The generated S3 backend config uses `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` from the environment (not hardcoded `test`).

| Variable                | Default                 | Description              |
| ----------------------- | ----------------------- | ------------------------ |
| `FLOCI_ENDPOINT`        | `http://localhost:4566` | Floci emulator endpoint  |
| `AWS_DEFAULT_REGION`    | `us-east-1`             | AWS region               |
| `AWS_ACCESS_KEY_ID`     | `test`                  | S3 backend access key    |
| `AWS_SECRET_ACCESS_KEY` | `test`                  | S3 backend secret key    |

### CTF fork (floci-ctf)

Against the hardened image, set IAM or operator root credentials before running.

Forensic lab: same as `compat-terraform`; OpenTofu applies can provision trail buckets when audit is enabled on the emulator.

```bash
export AWS_ACCESS_KEY_ID="$FLOCI_AUTH_ROOT_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY"
just test-opentofu
```

## Docker

```bash
cd compatibility-tests
docker build -f compat-opentofu/Dockerfile -t floci-compat-opentofu .
docker run --rm --network host floci-compat-opentofu
```
