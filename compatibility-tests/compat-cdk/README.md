# compat-cdk

AWS CDK v2 compatibility tests for [floci-ctf](https://github.com/kangwijen/floci-ctf). Deploys a small stack against the emulator and asserts resources via the AWS CLI.

## Running

```bash
# From compatibility-tests/
just test-cdk

# Or directly
./compat-cdk/run.sh
```

## Configuration

Bats helpers source [`../lib/ctf-env.sh`](../lib/ctf-env.sh) for `FLOCI_ENDPOINT` and AWS credentials.

| Variable                | Default                 | Description              |
| ----------------------- | ----------------------- | ------------------------ |
| `FLOCI_ENDPOINT`        | `http://localhost:4566` | Floci emulator endpoint  |
| `AWS_DEFAULT_REGION`    | `us-east-1`             | AWS region               |
| `AWS_ACCESS_KEY_ID`     | `test`                  | SigV4 access key         |
| `AWS_SECRET_ACCESS_KEY` | `test`                  | SigV4 secret key         |

### CTF fork (floci-ctf)

The CTF image enables IAM enforcement. Export registered credentials before running; `test`/`test` calls fail with `403`.

Audit exercise stacks can provision S3 log buckets and CloudTrail trails via CDK; verify delivery with operator credentials after `cdk deploy`.

```bash
export AWS_ACCESS_KEY_ID="$FLOCI_AUTH_ROOT_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY"
just test-cdk
```

## Docker

```bash
cd compatibility-tests
docker build -f compat-cdk/Dockerfile -t floci-compat-cdk .
docker run --rm --network host floci-compat-cdk
```
