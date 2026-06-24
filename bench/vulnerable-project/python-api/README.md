# Intentionally Vulnerable Python API

This project is a CyberAI benchmark fixture. It is intentionally vulnerable and must not be deployed to a real network.

The goal is to give CyberAI a stable Python target with ground truth. Each planted issue has an ID in `expected-findings.json`, a clear file location, and an expected category.

## Contents

- FastAPI application with SAST-relevant bugs.
- Vulnerable dependency pins in `requirements.txt`.
- Fake secret fixtures for secret scanners.
- A fake private key fixture in `secrets/fake_id_rsa`.
- Docker, Kubernetes, Terraform, and GitHub Actions misconfigurations.

## Run CyberAI

From the repository root:

```bash
cyberai scan bench/vulnerable-project/python-api --no-llm --summary pretty
```

For benchmark scoring:

```bash
bench/run-python-benchmark.sh
```

The benchmark writes reports to `bench/results/python-api/` and prints a simple precision/recall score against `expected-findings.json`.

## Safety

All credentials are fake benchmark fixtures. The app deliberately contains dangerous patterns such as SQL injection, command injection, unsafe deserialization, path traversal, SSRF, weak JWT handling, insecure cookies, and exposed infrastructure settings.
