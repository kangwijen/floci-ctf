# compat-terraform

Terraform compatibility tests for [floci-ctf](https://github.com/kangwijen/floci-ctf). Provisions S3/DynamoDB remote state backends and applies a sample configuration against the emulator.

## Running

```bash
# From compatibility-tests/
just test-terraform

# Or directly
./compat-terraform/run.sh
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

Against the hardened image, set IAM or operator root credentials so Terraform state operations and applies are authorized.

Forensic lab: Terraform can provision S3 buckets and CloudTrail trails; with `FLOCI_SERVICES_CLOUDTRAIL_AUDIT_ENABLED=true`, verify `AWSLogs/` objects after applies.

```bash
export AWS_ACCESS_KEY_ID="$FLOCI_AUTH_ROOT_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY"
just test-terraform
```

## Docker

```bash
cd compatibility-tests
docker build -f compat-terraform/Dockerfile -t floci-compat-terraform .
docker run --rm --network host floci-compat-terraform
```
