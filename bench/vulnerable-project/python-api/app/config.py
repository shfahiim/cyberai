"""Configuration with intentionally fake secrets for scanner benchmarks."""

DEBUG = True

# FAKE BENCHMARK SECRET: this is not a real credential.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"

# FAKE BENCHMARK SECRET: this is not a real credential.
GITHUB_TOKEN = "ghp_000000000000000000000000000000000000"

# FAKE BENCHMARK SECRET: hardcoded signing keys are intentionally unsafe.
JWT_SECRET = "benchmark-hardcoded-jwt-secret"

UPLOAD_ROOT = "uploads"
