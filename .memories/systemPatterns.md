# ZeroSSL Issuer System Patterns

## Architecture Overview

### Component Structure
```
├── API (api/)
│   └── v1alpha1/
│       ├── Issuer CRD definition
│       ├── Type definitions
│       └── DNS solver types
├── Controller (internal/controller/)
│   ├── Issuer reconciliation
│   ├── Certificate management
│   └── DNS solver validation
├── ZeroSSL Client (internal/zerossl/)
│   ├── API client
│   ├── Certificate operations
│   └── DNS validation methods
└── Configuration (config/)
    ├── CRDs
    ├── RBAC
    └── Deployment
```

## Design Patterns

### Controller Pattern
- Follows Kubernetes controller pattern
- Reconciliation loop for Issuer resources
- Watch-based event handling
- Status management and conditions

### Client-Server Pattern
- RESTful API client for ZeroSSL
- HTTP client with proper error handling
- JSON serialization/deserialization
- Rate limiting and retries

### Repository Pattern
- Kubernetes client for resource management
- Clear separation of concerns
- Abstracted resource operations
- Consistent error handling

### DNS Solver Pattern
- Domain-based solver selection
- Route53 DNS provider implementation
- DNS record validation flow
- Cert-manager compatible pattern

## Technical Decisions

### Language & Framework
- Go language for Kubernetes native development
- Kubebuilder framework for scaffolding
- Controller-runtime for controller implementation
- Standard Go HTTP client for API calls

### Resource Management
- Custom Resource Definitions (CRDs)
- Namespace-scoped resources
- Standard Kubernetes RBAC
- Resource validation via webhooks (optional)

### Security Model
- Non-root container execution
- Read-only filesystem
- Minimal container privileges
- Secure API key handling
- HTTPS for metrics endpoint
- AWS credential management for Route53

### Monitoring & Observability
- Prometheus metrics
- Health checks
- Readiness probes
- Detailed logging
- Error tracking

## Component Relationships

### Controller Dependencies
1. Kubernetes API server
2. cert-manager CRDs
3. ZeroSSL API
4. Metrics server
5. AWS Route53 API (for DNS solver)

### Data Flow
1. Certificate request creation
2. ZeroSSL API interaction
3. Secret management
4. Status updates
5. DNS validation flow:
   - DNS solver selection based on domain
   - TXT record creation requirements
   - DNS validation verification
   - Certificate retrieval

### Error Handling Strategy
1. Transient vs. permanent errors
2. Automatic retries
3. Exponential backoff
4. Clear error reporting
5. DNS validation specific errors

## Development Patterns

### Testing Strategy
1. Unit tests for components
2. Integration tests for controller
3. E2E tests for full workflow
4. Test fixtures and mocks
5. DNS solver specific tests

### Code Organization
1. Clear package boundaries
2. Dependency injection
3. Interface-based design
4. Consistent error handling
5. DNS solver abstraction for extensibility

### Deployment Strategy
1. Kubernetes manifests
2. Kustomize for configuration
3. Multi-arch container images
4. Resource limits and requests 