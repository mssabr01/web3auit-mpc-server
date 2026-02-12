# Offline Deployment Guide

This guide shows how to build, distribute, and run the web3audit-mpc container in a secure, internet-isolated environment.

## Security Model

The offline image includes all dependencies at build time, allowing runtime execution with **zero internet access** to:
- Prevent data exfiltration
- Block malicious downloads
- Ensure reproducible audits
- Enable air-gapped deployments

## Pre-installed Solidity Versions

The following compiler versions are baked in:
- 0.8.24, 0.8.23, 0.8.22, 0.8.21, 0.8.20
- 0.8.19, 0.8.18, 0.8.17, 0.8.16, 0.8.15
- 0.8.13, 0.8.12, 0.8.11, 0.8.10, 0.8.9
- 0.8.8, 0.8.7, 0.8.4
- 0.7.6, 0.6.12

## Build & Push

### 1. Build the offline image
```bash
docker build -f Dockerfile.offline -t web3audit-mpc:offline .
```

### 2. Tag for GitHub Container Registry
```bash
docker tag web3audit-mpc:offline ghcr.io/<your-username>/web3audit-mpc:latest
docker tag web3audit-mpc:offline ghcr.io/<your-username>/web3audit-mpc:$(date +%Y-%m-%d)
```

### 3. Authenticate with GitHub
```bash
echo $GITHUB_TOKEN | docker login ghcr.io -u <your-username> --password-stdin
```

### 4. Push to registry
```bash
docker push ghcr.io/<your-username>/web3audit-mpc:latest
docker push ghcr.io/<your-username>/web3audit-mpc:$(date +%Y-%m-%d)
```

## Usage

### Maximum Security (No Network)
```bash
docker run --network=none \
  -v $(pwd)/contracts:/contracts \
  ghcr.io/<your-username>/web3audit-mpc:latest
```

### With Read-Only Filesystem
```bash
docker run --network=none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=100m \
  -v $(pwd)/contracts:/contracts \
  ghcr.io/<your-username>/web3audit-mpc:latest
```

### Additional Hardening
```bash
docker run --network=none \
  --read-only \
  --tmpfs /tmp:rw,noexec,nosuid,size=100m \
  --cap-drop=ALL \
  --security-opt=no-new-privileges \
  --user 1000:1000 \
  -v $(pwd)/contracts:/contracts:ro \
  ghcr.io/<your-username>/web3audit-mpc:latest
```

## Verification

### Verify network isolation
```bash
# This should fail (no network)
docker run --network=none ghcr.io/<your-username>/web3audit-mpc:latest \
  sh -c "curl https://google.com"
```

### Check installed tools
```bash
docker run --network=none ghcr.io/<your-username>/web3audit-mpc:latest \
  sh -c "solc --version && slither --version && forge --version"
```

### List available Solidity versions
```bash
docker run --network=none ghcr.io/<your-username>/web3audit-mpc:latest \
  sh -c "solc-select versions"
```

## Image Size Comparison

Check the size difference:
```bash
docker images | grep web3audit-mpc
```

## Update Strategy

Since dependencies are frozen at build time:

1. **Monthly rebuilds** recommended for security patches
2. **Tag with dates** for version tracking
3. **Document build date** in your audit reports
4. **Pin to specific tags** in production workflows

## ⚠️ Limitations

- **Solc versions**: Limited to pre-installed versions (add more if needed)
- **Foundry updates**: Won't auto-update (by design)
- **NPM packages**: Aderyn version frozen at build time

## Network Policy Examples

### Docker Compose
```yaml
version: '3.8'
services:
  auditor:
    image: ghcr.io/<your-username>/web3audit-mpc:latest
    network_mode: none
    volumes:
      - ./contracts:/contracts:ro
    read_only: true
    tmpfs:
      - /tmp:rw,noexec,nosuid,size=100m
```

### Kubernetes
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: web3audit
spec:
  containers:
  - name: auditor
    image: ghcr.io/<your-username>/web3audit-mpc:latest
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      runAsNonRoot: true
      runAsUser: 1000
  hostNetwork: false
```

## Audit Trail

Document these in your audit reports:
- Image tag used (e.g., `2026-02-12`)
- Image digest (SHA256)
- Network configuration
- Build date
- Tool versions included

Example:
```bash
docker inspect ghcr.io/<your-username>/web3audit-mpc:latest \
  --format='{{.RepoDigests}}'
```
