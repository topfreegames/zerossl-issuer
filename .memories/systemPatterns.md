# ZeroSSL Issuer System Patterns

## Architecture Overview

### Component Structure
```
├── API (api/)
│   └── v1alpha1/
│       ├── Issuer CRD definition
│       └── Type definitions
├── Controller (internal/controller/)
│   ├── Issuer reconciliation
│   └── Certificate management
├── ZeroSSL Client (internal/zerossl/)
│   ├── API client
│   └── Certificate operations
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

### Data Flow
1. Certificate request creation
2. ZeroSSL API interaction
3. Secret management
4. Status updates

### Error Handling Strategy
1. Transient vs. permanent errors
2. Automatic retries
3. Exponential backoff
4. Clear error reporting

## Development Patterns

### Testing Strategy
1. Unit tests for components
2. Integration tests for controller
3. E2E tests for full workflow
4. Test fixtures and mocks

### Code Organization
1. Clear package boundaries
2. Dependency injection
3. Interface-based design
4. Consistent error handling

### Deployment Strategy
1. Kubernetes manifests
2. Kustomize for configuration
3. Multi-arch container images
4. Resource limits and requests 