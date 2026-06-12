#!/usr/bin/env bash
# Shared Floci endpoint and AWS credential exports for compatibility-tests.
#
# Permissive mode (upstream Floci / local dev without IAM enforcement):
#   AWS_ACCESS_KEY_ID=test, AWS_SECRET_ACCESS_KEY=test
#   Dummy credentials and unsigned requests are accepted.
#
# CTF fork (floci-ctf with IAM enforcement and SigV4 validation):
#   Export operator FLOCI_AUTH_ROOT_* or participant IAM keys from CreateAccessKey.
#   Set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY to registered credentials.
#   test/test and unsigned calls return 403.
#
# Forensic lab (floci-ctf Compose defaults):
#   FLOCI_STORAGE_MODE=hybrid, FLOCI_SERVICES_CLOUDTRAIL_AUDIT_ENABLED=true
#   Set FLOCI_CLOUDTRAIL_AUDIT_ENABLED=true for sdk-test-java forensic probes.
#
# Usage (from a module test_helper/common-setup.bash):
#   source "${MODULE_DIR}/../lib/ctf-env.sh"
#   # or in Docker images: source /opt/floci/ctf-env.sh

export FLOCI_ENDPOINT="${FLOCI_ENDPOINT:-http://localhost:4566}"
export AWS_DEFAULT_REGION="${AWS_DEFAULT_REGION:-us-east-1}"
export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-test}"
export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-test}"
export AWS_ENDPOINT_URL="${AWS_ENDPOINT_URL:-$FLOCI_ENDPOINT}"

# Hint for Java forensic probes (see TestFixtures.isCloudTrailAuditEnabled)
export FLOCI_CLOUDTRAIL_AUDIT_ENABLED="${FLOCI_CLOUDTRAIL_AUDIT_ENABLED:-false}"
export FLOCI_CTF_PROFILE="${FLOCI_CTF_PROFILE:-permissive}"
export FLOCI_IAM_ENFORCEMENT="${FLOCI_IAM_ENFORCEMENT:-false}"

# Returns 0 when credentials differ from permissive test/test (CTF or custom IAM).
is_ctf_credentials() {
    [[ "${AWS_ACCESS_KEY_ID}" != "test" || "${AWS_SECRET_ACCESS_KEY}" != "test" ]]
}

# Returns 0 when forensic audit delivery is expected (Compose or explicit env).
is_forensic_lab() {
    [[ "${FLOCI_CLOUDTRAIL_AUDIT_ENABLED}" == "true" ]]
}

# Apply CTF profile exports (operator root as AWS_* when set).
apply_ctf_profile() {
    export FLOCI_CTF_PROFILE="${FLOCI_CTF_PROFILE:-ctf}"
    export FLOCI_IAM_ENFORCEMENT="${FLOCI_IAM_ENFORCEMENT:-true}"
    if [[ -n "${FLOCI_AUTH_ROOT_ACCESS_KEY_ID:-}" && -n "${FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY:-}" ]]; then
        export AWS_ACCESS_KEY_ID="${AWS_ACCESS_KEY_ID:-$FLOCI_AUTH_ROOT_ACCESS_KEY_ID}"
        export AWS_SECRET_ACCESS_KEY="${AWS_SECRET_ACCESS_KEY:-$FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY}"
    fi
}

# Apply forensic lab hints for compatibility probes.
apply_forensic_profile() {
    apply_ctf_profile
    export FLOCI_CLOUDTRAIL_AUDIT_ENABLED="${FLOCI_CLOUDTRAIL_AUDIT_ENABLED:-true}"
}
