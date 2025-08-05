# ZeroSSL Issuer Technical Context

## Technology Stack

### Core Technologies
- Go 1.24
- Kubernetes 1.19+
- cert-manager v1.6.0+
- ZeroSSL API
- Docker/Containerd
- AWS Route53 API (for DNS solver)

### Development Tools
- Kubebuilder 4.7.0
- Kustomize
- Make
- GoLangCI-Lint
- Ginkgo (testing)

### Runtime Dependencies
- controller-runtime
- client-go
- api-machinery
- cert-manager API
- AWS SDK for Go v2

## Development Setup

### Prerequisites
1. Go 1.24+
2. Docker
3. Kubernetes cluster (for testing)
4. Kubebuilder
5. Make

### Build Commands
```bash
# Build binary
make build

# Run tests
make test

# Run e2e tests
make test-e2e

# Build container
make docker-build

# Generate manifests
make manifests
```

### Environment Variables
- `IMG`: Container image name/tag
- `CONTAINER_TOOL`: Container build tool (docker/podman)
- `KUBEBUILDER_ASSETS`: Test binary assets
- `CERT_MANAGER_INSTALL_SKIP`: Skip cert-manager installation in tests

## Technical Constraints

### API Limitations
- ZeroSSL API rate limits
- Certificate validity periods
- Domain validation methods (HTTP, DNS)
- API key requirements
- AWS credentials for Route53 access
- CNAME validation record requirements

### Resource Requirements
- Minimum memory: 64Mi
- Recommended memory: 128Mi
- Minimum CPU: 10m
- Recommended CPU: 500m

### Platform Requirements
- Linux-based container runtime
- Kubernetes API server access
- Network access to ZeroSSL API
- cert-manager installation
- AWS Route53 API access (for DNS solver)

### Security Constraints
- Non-root execution
- Read-only filesystem
- No privileged access
- Secure API key storage
- HTTPS for metrics
- Secure AWS credential management

## Dependencies

### Direct Dependencies
```go
k8s.io/client-go
k8s.io/api-machinery
sigs.k8s.io/controller-runtime
github.com/cert-manager/cert-manager
github.com/aws/aws-sdk-go-v2
```

### Indirect Dependencies
- Prometheus client
- Ginkgo/Gomega
- JSON encoding/decoding
- HTTP client

## Configuration

### CRD Configuration
- Group: zerossl.cert-manager.io
- Version: v1alpha1
- Kinds: 
  - Issuer
  - Challenge
- Scope: Namespaced
- DNS Solver Types:
  - Route53 configuration
  - Domain selectors
  - Credentials management

### Metrics Configuration
- Port: 8443 (HTTPS)
- Path: /metrics
- Authentication: Optional

### Health Probes
- Liveness: :8081/healthz
- Readiness: :8081/readyz
- Initial delay: 15s/5s

### Resource Limits
```yaml
resources:
  limits:
    cpu: 500m
    memory: 128Mi
  requests:
    cpu: 10m
    memory: 64Mi
```

## Deployment Architecture

### Container Image
- Base: distroless/static:nonroot
- Multi-arch support
- Minimal runtime
- Security hardened

### Kubernetes Resources
- Deployment
- Service Account
- RBAC roles/bindings
- CRDs
- Services
- Network Policies

### Helm Chart Features
- JSON Schema validation (Draft 2020-12)
- Comprehensive values validation
- Type checking and constraint validation
- Required field enforcement
- Configuration error prevention
- Enhanced user experience with clear error messages

### DNS Solver Configuration

#### Route53 Solver Example
```yaml
solvers:
- dns01:
    route53:
      accessKeyID: AKIAEXAMPLE
      hostedZoneID: Z2E9THH2A4HU6P
      region: us-east-1
      secretAccessKeySecretRef:
        key: secret
        name: route53-credentials
  selector:
    dnsZones:
    - example.com
```

#### Domain Selector Options
- dnsNames: Explicit domain list
- dnsZones: Domain zones for wildcard matching

### CNAME Validation Process
1. Certificate request creates certificate in ZeroSSL API
2. ZeroSSL provides CNAME validation details
3. Controller creates Challenge resource with validation records
4. Challenge controller creates CNAME records in Route53
5. Controller verifies DNS validation via ZeroSSL API
6. Certificate is issued after successful validation 